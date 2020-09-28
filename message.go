package ipc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sync"
)

const (
	opcode_RESPONSE = iota
	opcode_KEEPALIVE
	opcode_KEEPALIVE_ACCEPTED
	opcode_REQUEST
	opcode_NORESPONSE
	opcode_SECRET
	opcode_SECRET_ACCEPTED
	opcode_ISIPC
)

// Messages contain an OpCode, Data and a QueryID. Responses to a
// message that uses the REQUEST opcode should be created using the
// makeResponseWithData() or makeEmptyResponse() functions so that
// they bear the same QueryID ans their requesting Message.

// Message QueryIDs are generated using this counter. Once the counter
// reaches the maximum value for an unsigned 64-bit integer it will
// wrap back around to 0.
var queryIdCounter uint64 = 0
var queryIdCounterLock sync.Mutex

type message struct {
	OpCode  int
	Data    string
	QueryId uint64
}

func newMessage() *message {
	msg := &message{}
	msg.generateQueryID()
	return msg
}

func newMessageWithOpCode(opCode int) *message {
	msg := &message{
		OpCode: opCode,
		Data:   "",
	}

	msg.generateQueryID()
	return msg
}

func newMessageWithOpCodeAndData(opCode int, data string) *message {
	msg := &message{
		OpCode: opCode,
		Data:   data,
	}

	msg.generateQueryID()
	return msg
}

func newMessageWithData(data string) *message {
	msg := &message{
		OpCode: opcode_REQUEST,
		Data:   data,
	}

	msg.generateQueryID()
	return msg
}

func (m *message) generateQueryID() {
	queryIdCounterLock.Lock()
	id := queryIdCounter
	if queryIdCounter == math.MaxUint64 {
		queryIdCounter = 0
	} else {
		queryIdCounter = queryIdCounter + 1
	}
	m.QueryId = id
	queryIdCounterLock.Unlock()
}

func (m *message) makeResponseWithData(data string) *message {
	return &message{
		OpCode:  opcode_RESPONSE,
		Data:    data,
		QueryId: m.QueryId,
	}
}

func (m *message) makeEmptyResponse() *message {
	return &message{
		OpCode:  opcode_NORESPONSE,
		Data:    "",
		QueryId: m.QueryId,
	}
}

func (m *message) decode(data string) error {
	decoded, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return fmt.Errorf("failed to decode message: %v", err)
	}

	decoded, err = decrypt(decoded)
	if err != nil {
		return fmt.Errorf("failed to decode message: %v", err)
	}

	err = json.Unmarshal(decoded, m)
	if err != nil {
		return fmt.Errorf("failed to decode message: %v", err)
	}

	return nil
}

func (m *message) encode() (string, error) {
	marshaled, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to encode message: %v", err)
	}

	encrypted, err := encrypt(marshaled)
	if err != nil {
		return "", fmt.Errorf("failed to encode message: %v", err)
	}

	return base64.RawStdEncoding.EncodeToString(encrypted), nil
}
