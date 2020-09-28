package ipc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// QueryHandler is used for handling queries from the other end of
// the IPC tunnel. It will receive the query and should respond with a
// response. If you do not have a response, return an empty string.
type QueryHandler func(string) string

// NotConnected represents an error message result from the Query
// function indicating that you are trying to send a Query while the
// peer is not connected.
var NotConnected error = fmt.Errorf(
	"%s", "query: cannot query while not connected",
)

// Connection represents an IPC Connection between two processes.
type Connection struct {
	runningAsServer  bool
	clientConnection *ioHandler
	serverConnection *ioHandler
	serverListener   net.Listener
	closeServer      chan bool

	// Spec contains the connection specification that this connection
	// is using to communicate with the other process.
	Spec *Spec

	// QueryHandler contains the QueryHandler to use for queries.
	QueryHandler QueryHandler

	// QueryTimeout is the timeout value used for all I/O operations
	// and query responses. The default value is 5 seconds.
	QueryTimeout time.Duration

	// Reconnect indicates whether or not to re-connect in the event
	// of a dropped connetion when running as a client. By default,
	// when running as a client, this feature is enabled.
	Reconnect bool

	// ReconnectMaxRetries is the maximum number of attempts that can
	// be made to reconnect before totally dropping the connection. A
	// zero value indicates unlimited retries and is the default value.
	ReconnectMaxRetries int

	// ReconnectDelay is the amount of time to wait between each
	// reconnect attempt. The default value is one second.
	ReconnectDelay time.Duration
}

// NewConnection creates a new Connetion using the specified connection
// specification and query handler.
func NewConnection(
	spec *Spec,
	queryHandler QueryHandler,
) *Connection {
	return &Connection{
		closeServer:         make(chan bool),
		Spec:                spec,
		QueryHandler:        queryHandler,
		Reconnect:           true,
		ReconnectMaxRetries: 0,
		ReconnectDelay:      time.Second,
	}
}

// IsConnected determines if the Connection is currently connected to
// a peer process.
func (connection *Connection) IsConnected() bool {
	if connection.runningAsServer {
		return connection.serverConnection != nil
	}

	return connection.clientConnection != nil
}

// Connect will connect to the other end of the IPC connection. If
// this is the first process to call this function, it will run as a
// server. Otherwise, if this is the second process to call this
// function, it will connect to the first process. This function will
// return nil upon success. If this function returns an error it will
// not automatically attempt to reconnect. Once this function returns
// successfully, it will attempt to automatically recover in the event
// of a future drop of connection.
func (connection *Connection) Connect() error {
	debugLog(
		"initializing connection with spec: %v",
		connection.Spec.toString(),
	)

	var server net.Listener
	var err error

	// We first attempt to connect to a running server if one exists.
	//
	// If we find a server, we send it a message with opcode_ISIPC to
	// determine if it is a valid IPC server. If it responds with the
	// same opcode, we consider it a valid IPC server, close the
	// client connection we used to make the determination and connect
	// to it as an IPC client. Otherwise, we fail and assume that
	// another application is using the address.
	var invClient net.Conn
	var invErr error
	if connection.Spec.useTls {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(connection.Spec.tlsCertBytes)

		conf := &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521, tls.CurveP384, tls.CurveP256,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			InsecureSkipVerify: true, // Not actually skipping,
			// we check the cert in the
			// VerifyPeerCertificate function.
			VerifyPeerCertificate: func(
				rawCerts [][]byte,
				verifiedChains [][]*x509.Certificate,
			) error {
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
		invClient, invErr = tls.Dial(
			connection.Spec.Type,
			connection.Spec.Address,
			conf,
		)
	} else {
		invClient, invErr = net.Dial(
			connection.Spec.Type,
			connection.Spec.Address,
		)
	}
	if invErr == nil {
		isIPC := newMessageWithOpCode(opcode_ISIPC)
		h := newIOHandler(invClient, connection.QueryTimeout)
		err = h.sendMessageWithoutResponse(isIPC)
		if err != nil {
			return fmt.Errorf(
				"%v %v, %v: %v",
				"found server running on address",
				connection.Spec.Address,
				"but failed to communicate with it",
				err,
			)
		}

		resp, err := h.nextMessage()
		if err != nil {
			return fmt.Errorf(
				"%v %v, %v: %v",
				"found server running on address",
				connection.Spec.Address,
				"but failed to communicate with it",
				err,
			)
		}

		if resp.OpCode != opcode_ISIPC {
			return fmt.Errorf(
				"%v %v, %v (%v)",
				"found server running on address",
				connection.Spec.Address,
				"but it responded with an invalid opcode",
				resp.OpCode,
			)
		}

		// At this point the server has confirmed that it is a valid
		// IPC instance and we can attempt a connection
		invClient.Close()

		// assume that the server is already running
		debugLog(
			"found ipc server running on address %v; starting client",
			connection.Spec.Address,
		)
		return connection.runClient()
	}

	// Since we have determined that the address is not in use we can
	// now start a server there.
	if connection.Spec.useTls {
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521, tls.CurveP384, tls.CurveP256,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			Certificates: []tls.Certificate{connection.Spec.tlsCert},
		}
		server, err = tls.Listen(
			connection.Spec.Type,
			connection.Spec.Address,
			config,
		)
	} else {
		server, err = net.Listen(
			connection.Spec.Type,
			connection.Spec.Address,
		)
	}

	if err != nil {
		return err
	}

	debugLog(
		"starting server on address %v",
		connection.Spec.Address,
	)
	connection.runningAsServer = true
	go connection.runServer(server)
	return nil
}

// Close will cleanly close the connection. If no connection is open,
// a message will be written to the debug log.
func (connection *Connection) Close() {
	if !connection.IsConnected() {
		debugLog(
			"attempting to close connection but no connection active",
		)
		return
	}

	debugLog("closing connection")
	defer debugLog("connection closed")
	if connection.serverConnection != nil {
		// Close the connection to the client
		connection.serverConnection.doClose()
		// Stop listening for new connections
		close(connection.closeServer)
		connection.serverListener.Close()
		return
	}

	if connection.clientConnection != nil {
		// Close the connection to the server
		connection.clientConnection.doClose()
	}
}

// Query will query the other side of the connection with a message.
// If the side of the connection is not available, this function will
// return an empty string and the ipc.NotConnected error. It may
// return other errors in the event of an error.
func (connection *Connection) Query(query string) (string, error) {
	message := newMessageWithData(query)
	if logQueries {
		debugLog(
			"sending query with id %v: %v",
			message.QueryId,
			message.Data,
		)
	}

	if connection.serverConnection != nil {
		m, err := connection.serverConnection.sendMessage(message)
		if err != nil {
			return "", err
		}

		return m.Data, nil
	}

	if connection.clientConnection != nil {
		m, err := connection.clientConnection.sendMessage(message)
		if err != nil {
			return "", err
		}

		return m.Data, nil
	}

	return "", NotConnected
}

func (connection *Connection) runClient() error {
	var client net.Conn
	var err error

	if connection.Spec.useTls {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(connection.Spec.tlsCertBytes)

		conf := &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521, tls.CurveP384, tls.CurveP256,
			},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			InsecureSkipVerify: true, // Not actually skipping,
			// we check the cert in the
			// VerifyPeerCertificate function.
			VerifyPeerCertificate: func(
				rawCerts [][]byte,
				verifiedChains [][]*x509.Certificate,
			) error {
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
		client, err = tls.Dial(
			connection.Spec.Type,
			connection.Spec.Address,
			conf,
		)
	} else {
		client, err = net.Dial(
			connection.Spec.Type,
			connection.Spec.Address,
		)
	}

	if err != nil {
		errorLog("failed to connect to server: %v", err)
		return err
	}

	debugLog("connected to server")

	io := newIOHandler(client, connection.QueryTimeout)

	debugLog("sending secret to server: %v", connection.Spec.Secret)

	// Send the secret to the peer.
	secret := newMessageWithOpCodeAndData(
		opcode_SECRET,
		connection.Spec.Secret,
	)
	err = io.sendMessageWithoutResponse(secret)
	if err != nil {
		errorLog("failed to send message to server: %v", err)
		return err
	}

	debugLog("awaiting response from server")

	// Read the response from the peer
	message, err := io.nextMessage()
	if err != nil {
		errorLog("failed to read message from server: %v", err)
		return err
	}

	// Validate the secret
	if message.OpCode != opcode_SECRET_ACCEPTED {
		errorLog("server did not accept secret")
		return fmt.Errorf("peer did not accept secret")
	}

	debugLog("server accepted secret")

	// Start listening for communication
	go func() {
		debugLog("starting communication cycle")
		err := io.listen(connection.QueryHandler, true)
		if err != nil {
			errorLog("lost connection: %v\n", err)

			connection.clientConnection = nil
			if connection.Reconnect {
				debugLog(
					"attempting reconnect with %v maximum retries",
					connection.ReconnectMaxRetries,
				)
				i := 1
				for {
					if i <= connection.ReconnectMaxRetries ||
						connection.ReconnectMaxRetries == 0 {
						err := connection.runClient()
						if err == nil {
							break
						}
						time.Sleep(connection.ReconnectDelay)
					}
					i += 1
				}
			}
		}
	}()

	// Return successfully
	connection.clientConnection = io
	return nil
}

func (connection *Connection) runServer(listener net.Listener) {
	connection.serverListener = listener
	defer func() {
		listener.Close()
		debugLog("connection closed")
	}()

	for {
		peer, err := listener.Accept()
		if err != nil {
			select {
			case <-connection.closeServer:
				return
			default:
			}
			errorLog("failed to accept connection: %v\n", err)
			continue
		}

		// We do not run this in a go-routine. The idea here
		// is that only one client and one server can ever
		// run at any given time, so we shouldn't need to
		// accept any more than one peer at a time.
		err = connection.handlePeer(peer)
		if err != nil {
			errorLog("dropped connection: %v\n", err)
			connection.serverConnection = nil
		}
	}
}

func (connection *Connection) handlePeer(peer net.Conn) error {
	// Create IO Handler
	io := newIOHandler(peer, connection.QueryTimeout)

	message, err := io.nextMessage()
	if err != nil {
		return err
	}

	// A new connection will first try to determine if this is
	// a valid IPC connection using a separate "ping" connection.
	//
	// For these connections we should just echo the request and
	// drop the connection gracefully.
	if message.OpCode == opcode_ISIPC {
		isIPCAccepted := newMessageWithOpCode(opcode_ISIPC)
		// Ignore egress errors for ISIPC opcodes
		io.sendMessageWithoutResponse(isIPCAccepted)
		return nil
	}

	// The first message from a real connection should be the
	// IPC secret and we should compare it to the secret stored
	// in the connection.
	if message.OpCode != opcode_SECRET {
		return fmt.Errorf(
			"invalid initial OPCODE, expected opcode_SECRET",
		)
	}

	if message.Data != connection.Spec.Secret {
		return fmt.Errorf(
			"dropping connection due to invalid secret",
		)
	}

	// Respond with secret accepted
	debugLog("responding with secret accepted")
	secretAccepted := newMessageWithOpCode(opcode_SECRET_ACCEPTED)
	err = io.sendMessageWithoutResponse(secretAccepted)
	if err != nil {
		return err
	}

	// Return successfully
	connection.serverConnection = io
	debugLog("starting communication cycle")
	return io.listen(connection.QueryHandler, false)
}
