package ipc

import (
    "fmt"
    "time"
    "net"
    "crypto/tls"
    "crypto/x509"
    "strings"
)

type MessageHandler func(string) string

type Connection struct {
    acceptConnections   bool
    runningAsServer     bool

    clientConnection    *ioHandler
    serverConnection    *ioHandler

    Spec                *Spec
    MessageHandler      MessageHandler
    QueryTimeout        time.Duration

    Reconnect           bool
    ReconnectMaxRetries int
    ReconnectDelay      time.Duration
}

func NewConnection(spec *Spec, messageHandler MessageHandler) *Connection {
    return &Connection{
        Spec: spec,
        MessageHandler: messageHandler,
        Reconnect: true,
        ReconnectMaxRetries: 0,
        ReconnectDelay: time.Second,
    }
}

func (connection *Connection) IsConnected() bool {
    if connection.runningAsServer {
        return connection.serverConnection != nil
    }

    return connection.clientConnection != nil
}

func (connection *Connection) Connect() error {
    var server net.Listener
    var err    error
    if connection.Spec.useTls {
        config := &tls.Config{
            MinVersion:               tls.VersionTLS12,
            CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
            PreferServerCipherSuites: true,
            CipherSuites: []uint16{
                tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_RSA_WITH_AES_256_CBC_SHA,
            },
            Certificates: []tls.Certificate{connection.Spec.tlsCert},
        }
        server, err = tls.Listen(connection.Spec.Type, connection.Spec.Address, config)
    } else {
        server,err = net.Listen(connection.Spec.Type, connection.Spec.Address)
    }

    if err != nil {
        if strings.Contains(fmt.Sprintf("%v", err), "address already in use") {
            // assume that the server is already running and connect to it
            return connection.runClient()
        }
        return err
    }

    connection.runningAsServer   = true
    go connection.runServer(server)
    return nil
}

func (connection *Connection) Query(query string) (string, error) {
    messageToSend := newMessageWithData(query)

    if connection.serverConnection != nil {
        m, err := connection.serverConnection.sendMessage(messageToSend)
        if err != nil {
            return "", err
        }

        return m.Data,nil
    }

    if connection.clientConnection != nil {
        m,err := connection.clientConnection.sendMessage(messageToSend)
        if err != nil {
            return "",err
        }

        return m.Data,nil
    }

    return "", fmt.Errorf("%s\n", "query: cannot query while not connected")
}

func (connection *Connection) runClient() error {
    var client net.Conn
    var err    error

    if connection.Spec.useTls {
        certPool := x509.NewCertPool()
    	certPool.AppendCertsFromPEM(connection.Spec.tlsCertBytes)

        conf := &tls.Config{
            RootCAs: certPool,
            MinVersion:               tls.VersionTLS12,
            CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
            PreferServerCipherSuites: true,
            CipherSuites: []uint16{
                tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
                tls.TLS_RSA_WITH_AES_256_CBC_SHA,
            },
            InsecureSkipVerify: true, // Not actually skipping, we check the cert in VerifyPeerCertificate
            VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
                certs := make([]*x509.Certificate, len(rawCerts))
                for i, asn1Data := range rawCerts {
                    cert, err := x509.ParseCertificate(asn1Data)
                    if err != nil {
                        return err
                    }
                    certs[i] = cert
                }
    
                opts := x509.VerifyOptions{
                    Roots:         certPool,
                    CurrentTime:   time.Now(),
                    DNSName:       "", // <- skip hostname verification
                    Intermediates: x509.NewCertPool(),
                }
    
                for i, cert := range certs {
                    if i == 0 {
                        continue
                    }
                    opts.Intermediates.AddCert(cert)
                }
                _, err := certs[0].Verify(opts)
                return err
            },
        }
        client, err = tls.Dial(connection.Spec.Type, connection.Spec.Address, conf)
    } else {
        client, err = net.Dial(connection.Spec.Type, connection.Spec.Address)
    }

    if err != nil {
        return err
    }

    io := newIOHandler(client, connection.QueryTimeout)
    
    secret := newMessageWithOpCodeAndData(opcode_SECRET, connection.Spec.Secret)
    err = io.sendMessageWithoutResponse(secret)
    if err != nil {
        return err
    }

    message,err := io.nextMessage()
    if err != nil {
        return err
    }

    if message.OpCode != opcode_SECRET_ACCEPTED {
        return fmt.Errorf("peer did not accept secret")
    }

    go func() {
        err := io.listen(connection.MessageHandler, true)
        if err != nil {
            fmt.Printf("lost connection: %v\n", err)
        }
        connection.clientConnection = nil
        if connection.Reconnect {
            i := 1
            for {
                if i <= connection.ReconnectMaxRetries || connection.ReconnectMaxRetries == 0 {
                    err := connection.runClient()
                    if err == nil {
                        break
                    }
                    time.Sleep(connection.ReconnectDelay)
                }
                i += 1
            }
        }
    }()
    connection.clientConnection = io
    return nil
}

func (connection *Connection) runServer(listener net.Listener) {
    connection.acceptConnections = true
    defer listener.Close()

    for connection.acceptConnections {
        peer,err := listener.Accept()
        if err != nil {
            fmt.Printf("failed to accept connection: %v\n", err)
            continue
        }

        err = connection.handlePeer(peer)
        if err != nil {
            fmt.Printf("dropped connection: %v\n", err)
            connection.serverConnection = nil
        }
    }
}

func (connection *Connection) handlePeer(peer net.Conn) (error) {
    // Create IO Handler
    io := newIOHandler(peer, time.Second * 5000000000)

    // Negotiate Secret
    message,err := io.nextMessage()
    if err != nil {
        return err
    }

    if message.OpCode != opcode_SECRET {
        return fmt.Errorf("Invalid initial OPCODE, expected opcode_SECRET")
    }

    if message.Data != connection.Spec.Secret {
        return fmt.Errorf("Dropping connection due to invalid secret")
    }

    secretAccepted := newMessageWithOpCode(opcode_SECRET_ACCEPTED)
    err = io.sendMessageWithoutResponse(secretAccepted)
    if err != nil {
        return err
    }

    connection.serverConnection = io

    return io.listen(connection.MessageHandler, false)
}