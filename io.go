package ipc

import (
    "fmt"
    "net"
    "bufio"
    "strings"
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
}

func newIOHandler(peer net.Conn, timeout time.Duration) *ioHandler {
    return &ioHandler {
        peer: peer,
        timeout: timeout,
        responseHandlers: map[uint64]*handler{},
    }
}

func (handler *ioHandler) listen(msghandler MessageHandler, keepalive bool) error {
    // Keep alive
    if keepalive {
        go func() {
            for {
                output := newMessageWithOpCode(opcode_KEEPALIVE)
                err := handler.sendMessageWithoutResponse(output)
                
                if err != nil {
                    break
                }

                timeout := handler.timeout
                if timeout == time.Duration(0) {
                    timeout = time.Second * 5
                }
                time.Sleep(timeout / 2)
            }
        }()
    }

    for {
        input, err := handler.nextMessage()
        if err != nil {
            handler.close()
            return err
        }

        // Handle keep alive packets
        if input.OpCode == opcode_KEEPALIVE {
            accepted := newMessageWithOpCode(opcode_KEEPALIVE_ACCEPTED)
            handler.sendMessageWithoutResponse(accepted)
            continue
        }

        if input.OpCode == opcode_KEEPALIVE_ACCEPTED {
            continue
        }

        // This means it is a response to a query
        if input.OpCode == opcode_RESPONSE || input.OpCode == opcode_NORESPONSE {
            if resph,exists := handler.responseHandlers[input.QueryId]; exists {
                go resph.handle(input)
                continue
            }
        }

        // Otherwise, it is a query and we should respond
        if input.OpCode == opcode_REQUEST {
            outputstr := msghandler(input.Data)
            output := input.makeResponseWithData(outputstr)
            if len(outputstr) < 1 {
                output = input.makeEmptyResponse()
            }

            err = handler.sendMessageWithoutResponse(output)
            if err != nil {
                handler.close()
                return err
            }
        }
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
        return nil, fmt.Errorf("failed to read message from peer: %v", err)
    }

    data = strings.TrimSuffix(data, "\n")
    output := newMessage()
    err = output.decode(data)
    if err != nil {
        return nil, fmt.Errorf("ingress: %v", err)
    }

    return output, nil
}

func (io *ioHandler) sendMessageWithoutResponse(message *message) error {
    encoded,err := message.encode()
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
    timeoutChan := make(chan bool)
    handler := &handler{
        output: make(chan *message),
        handle: func(msg *message) {
            if handler, exists := io.responseHandlers[msg.QueryId]; exists {
                handler.output <- msg
            }
        },
    }

    io.responseHandlers[msg.QueryId] = handler
    defer delete(io.responseHandlers, msg.QueryId)

    err := io.sendMessageWithoutResponse(msg)
    if err != nil {
        return nil, err
    }

    go func() {
        timeout := io.timeout
        if timeout == time.Duration(0) {
            timeout = time.Second * 5
        }
        time.Sleep(timeout)
        timeoutChan <- true
    }()

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

func (io *ioHandler) close() {
    io.peer.Close()
}