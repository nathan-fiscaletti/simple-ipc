package ipc

import (
    "fmt"
    "crypto/tls"
    "io/ioutil"
)

// Spec represents the specification for an IPC connection
type Spec struct {
    // The connection type. This can be any of the following: "tcp",
    // "tcp4", "tcp6", or "unix"
    Type         string
    // When using "tcp", "tcp4", or "tcp6" this should be the
    // "host:port" formatted address. When using "unix", this should
    // be the path to the file you wish to use for the unix socket.
    Address      string
    // The secret that is communicated upon first connection to verify
    // that the peer belongs to this IPC connection.
    Secret       string

    useTls       bool
    tlsCert      tls.Certificate
    tlsCertBytes []byte
}

func (spec *Spec) toString() string {
    return fmt.Sprintf(
        "Type: %v, Address: %v, Secret: %v, TLS: %v",
        spec.Type,
        spec.Address,
        spec.Secret,
        spec.useTls,
    )
}

// NewSpec creates a new insecure connection specification using the
// specified type, address and secret.
func NewSpec(hType string, address string, secret string) *Spec {
    return &Spec{
        Type:    hType,
        Address: address,
        Secret:  secret,
        useTls:  false,
    }
}

// NewTLSSpec creates a new secure connection specification using the
// specified type, address and secret. The file paths to your TLS
// certificcate and key should be passed in the crt and key parameters.
func NewTLSSpec(hType string, address string, 
                crt string, key string, secret string) (*Spec, error) {
    cerbytes, err := ioutil.ReadFile(crt)
    if err != nil {
        return nil, err
    }
    cer, err := tls.LoadX509KeyPair(crt, key)
    if err != nil {
        return nil, err
    }

    return &Spec{
        Type:         hType,
        Address:      address,
        Secret:       secret,
        useTls:       true,
        tlsCert:      cer,
        tlsCertBytes: cerbytes,
    }, nil
}

// NewTCPSpec creates a new insecure TCP connection specification
// using the provided port and secret.
func NewTCPSpec(port int, secret string) *Spec {
    return &Spec{
        Type: "tcp",
        Address: fmt.Sprintf(":%d", port),
        Secret: secret,
        useTls:  false,
    }
}

// NewUnixSpec creates a new insecure Unix connection specification
// using the provided socket and secret.
func NewUnixSpec(socket string, secret string) *Spec {
    return &Spec{
        Type: "unix",
        Address: socket,
        Secret: secret,
        useTls:  false,
    }
}