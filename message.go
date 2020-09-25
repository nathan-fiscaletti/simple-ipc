package ipc

import (
    "encoding/base64"
    "encoding/json"
    "sync"
    "fmt"
)

const (
    opcode_RESPONSE = iota
    opcode_KEEPALIVE
    opcode_KEEPALIVE_ACCEPTED
    opcode_REQUEST
    opcode_TERMINATE
    opcode_NORESPONSE
    opcode_SECRET
    opcode_SECRET_ACCEPTED
)

var packetIdCounter     uint64 = 0
var packetIdCounterLock sync.Mutex

type message struct {
    OpCode  int
    Data    string
    QueryId uint64
}

func newMessage() *message {
    msg := &message {}
    msg.generateQueryID()
    return msg
}

func newMessageWithOpCode(opCode int) *message {
    msg := &message {
        OpCode: opCode,
        Data: "",
    }

    msg.generateQueryID()
    return msg
}

func newMessageWithOpCodeAndData(opCode int, data string) *message {
    msg := &message {
        OpCode: opCode,
        Data: data,
    }

    msg.generateQueryID()
    return msg
}

func newMessageWithData(data string) *message {
    msg := &message {
        OpCode: opcode_REQUEST,
        Data: data,
    }

    msg.generateQueryID()
    return msg
}

func (m *message) generateQueryID() {
    packetIdCounterLock.Lock()
    id := packetIdCounter
    packetIdCounter = packetIdCounter + 1
    m.QueryId = id
    packetIdCounterLock.Unlock()
}

func (m *message) makeResponseWithData(data string) *message {
    return &message{
        OpCode: opcode_RESPONSE,
        Data: data,
        QueryId: m.QueryId,
    }
}

func (m *message) makeEmptyResponse() *message {
    return &message{
        OpCode: opcode_NORESPONSE,
        Data: "",
        QueryId: m.QueryId,
    }
}

func (m *message) decode(data string) error {
    decoded, err := base64.RawStdEncoding.DecodeString(data)
    if err != nil {
        return fmt.Errorf("failed to decode message: %v", err)
    }

    decoded,err = decrypt(decoded)
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

