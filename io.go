package ipc

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type handler struct {
	output chan *message
	handle func(*message)
}

type ioHandler struct {
	peer             net.Conn
	timeout          time.Duration
	responseHandlers map[uint64]*handler

	close          chan bool
	closeKeepAlive chan bool

	closed sync.WaitGroup
}

func newIOHandler(peer net.Conn, timeout time.Duration) *ioHandler {
	return &ioHandler{
		peer:             peer,
		timeout:          timeout,
		responseHandlers: map[uint64]*handler{},
		close:            make(chan bool),
		closeKeepAlive:   make(chan bool),
	}
}

func (handler *ioHandler) listen(
	queryhandler QueryHandler,
	keepalive bool,
) error {
	if keepalive {
		debugLog("starting keep-alive thread for client")
		handler.closed.Add(1)
		// Only clients should ever provide a true value to the
		// keepalive variable. In this instance we will start a new
		// goroutine that will send a keepalive packet at an interval
		// that is 1/2 that of the I/O timeout.
		go func() {
			defer func() {
				debugLog("keep-alive routine closed")
				handler.closed.Done()
			}()

		KEEPALIVE:
			for {
				if logKeepAlives {
					debugLog("sending keep-alive packet")
				}
				output := newMessageWithOpCode(opcode_KEEPALIVE)
				err := handler.sendMessageWithoutResponse(output)

				if err != nil {
					break
				}

				timeout := handler.timeout
				if timeout == time.Duration(0) {
					timeout = time.Second * 5
				}

				select {
				case <-handler.closeKeepAlive:
					return
				case <-time.After(timeout / 2):
					continue KEEPALIVE
				}
			}
		}()
	}

	handler.closed.Add(1)

	defer func() {
		debugLog("listen routine closed")
		handler.closed.Done()
	}()

	for {
		// Read the next message from the handler
		input, err := handler.nextMessage()
		if err != nil {
			select {
			case <-handler.close:
				return nil
			default:
			}

			return err
		}

		// Handle keep alive packets
		if input.OpCode == opcode_KEEPALIVE {
			if logKeepAlives {
				debugLog("received keep-alive packet from client")
			}
			accepted := newMessageWithOpCode(opcode_KEEPALIVE_ACCEPTED)
			err := handler.sendMessageWithoutResponse(accepted)
			if err != nil {
				select {
				case <-handler.close:
					return nil
				default:
				}

				return err
			}
			continue
		}

		// Drop keep alive echo replies
		if input.OpCode == opcode_KEEPALIVE_ACCEPTED {
			if logKeepAlives {
				debugLog("server accepted keep-alive packet")
			}
			continue
		}

		// Handle query responses
		if input.OpCode == opcode_RESPONSE ||
			input.OpCode == opcode_NORESPONSE {
			if logQueries {
				debugLog(
					"received response for query with id %v: %v",
					input.QueryId, input.Data,
				)
			}
			r, exists := handler.responseHandlers[input.QueryId]
			if exists {
				go r.handle(input)
				continue
			}
		}

		// Otherwise, it is a query and we should respond
		if input.OpCode == opcode_REQUEST {
			if logQueries {
				debugLog(
					"received query with id %v: %v",
					input.QueryId,
					input.Data,
				)
			}
			outputstr := queryhandler(input.Data)
			output := input.makeResponseWithData(outputstr)
			if logQueries {
				debugLog(
					"sending query response for query with id %v: %v",
					output.QueryId,
					output.Data,
				)
			}
			if len(outputstr) < 1 {
				output = input.makeEmptyResponse()
			}

			err = handler.sendMessageWithoutResponse(output)
			if err != nil {
				select {
				case <-handler.close:
					return nil
				default:
				}

				errorLog("failed to send packet: %v", err)
			}

			continue
		}

		errorLog("unknown op-code in message: %v\n", input.OpCode)
	}
}

func (handler *ioHandler) nextMessage() (*message, error) {
	timeout := handler.timeout
	if timeout == time.Duration(0) {
		timeout = time.Second * 5
	}
	handler.peer.SetReadDeadline(time.Now().Add(timeout))
	data, err := bufio.NewReader(handler.peer).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read from peer: %v", err)
	}

	data = strings.TrimSuffix(data, "\n")
	output := newMessage()
	err = output.decode(data)
	if err != nil {
		return nil, fmt.Errorf("ingress: %v", err)
	}

	return output, nil
}

func (io *ioHandler) sendMessageWithoutResponse(
	message *message,
) error {
	encoded, err := message.encode()
	if err != nil {
		return err
	}

	timeout := io.timeout
	if timeout == time.Duration(0) {
		timeout = time.Second * 5
	}
	io.peer.SetWriteDeadline(time.Now().Add(timeout))
	writer := bufio.NewWriter(io.peer)
	_, err = writer.WriteString(fmt.Sprintf("%v\n", encoded))
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}

	return nil
}

func (io *ioHandler) sendMessage(msg *message) (*message, error) {
	// Create the timeout channel for awaiting the response
	timeoutChan := make(chan bool)

	// Add the handler to the list of handlers with an output channel
	// and the handler which should call the output channel with the
	// response message.
	handler := &handler{
		output: make(chan *message),
		handle: func(msg *message) {
			handler, exists := io.responseHandlers[msg.QueryId]
			if exists {
				handler.output <- msg
			}
		},
	}

	// Add the response handler to the static handlers and defer it's
	// deletion until the return of this function.
	io.responseHandlers[msg.QueryId] = handler
	defer delete(io.responseHandlers, msg.QueryId)

	// Send the message directly to the other end of the IPC tunnel.
	err := io.sendMessageWithoutResponse(msg)
	if err != nil {
		return nil, err
	}

	// Start the timeout goroutine
	go func() {
		timeout := io.timeout
		if timeout == time.Duration(0) {
			timeout = time.Second * 5
		}
		time.Sleep(timeout)

		// If enough time has elapsed, signal the timeout channel.
		timeoutChan <- true
	}()

	// Await either a signal from the response channel or a timeout
	select {
	case m := <-io.responseHandlers[msg.QueryId].output:
		if m.OpCode == opcode_NORESPONSE {
			return nil, nil
		}

		return m, nil
	case <-timeoutChan:
		return nil, fmt.Errorf("timed out while awaiting response")
	}
}

func (handler *ioHandler) doClose() {
	close(handler.closeKeepAlive)
	close(handler.close)
	handler.peer.Close()
	handler.closed.Wait()
}
