# Simple IPC

## Description

**The Problem**: Most rudimentary IPC implementations rely on a Client/Server mechanism in which you implement the server in one process and the client in another. This means the code you use must differ between each process.

**TheSolution**: Simple IPC aims to add support for basic messaging between two processes while maintaining an identical implementation for both the server and the client. This provides a very simple tunnel between the processes without having to worry about any of the networking.

```sh
$ go get github.com/nathan-fiscaletti/simple-ipc
```

```go
package main

import(
    ...

    "github.com/nathan-fiscaletti/simple-ipc"
)
```

## Basic Example

The following example can run as a client and a server. 

```go
package main

import(
    "fmt"
    "time"

    "github.com/nathan-fiscaletti/simple-ipc"
)

func main() {
    // Create the specification
    spec := ipc.NewTCPSpec(1234, "super-secret")

    // Create the Connection with a Message Handler
    connection := ipc.NewConnection(spec, func(message string) string {
        if message == "hello" {
            return "world"
        }

        return ""
    })

    // Connect
    err := connection.Connect()
    if err != nil {
        panic(err)
    }

    // Send Queries
    for {
        response,err := connection.Query("hello")
        if err != nil {
            fmt.Printf("query error: %v\n", err)
        }
        if response != "" { 
            fmt.Printf("query response: %v\n", response)
        }

        time.Sleep(time.Second * 2)
    }
}

```

## Connection Specifications

You can customize how your IPC connection works using a Connection Specification.

A connection specification is built up of three parts of data.

   1. The `Type`.

       This can be any of `tcp`, `tcp4`, `tcp6` or `unix`.

   2. The `Address`.

       The Address differs based on the `Type` field. 

   3. The `Secret`.

       The Secret is communicated to the server upon first connection to verify that the two processes are intended to communicate with each-other.

See the [Go: `net` Documentation](https://golang.org/pkg/net/) for more information on what each of these do and how they affect the `Address` field.

There are several helper functions to create Connection Specifications.

|Function|Description|
|---|---|
|`NewSpec`|Creates a new insecure connection specification using the provided type, address and secret.|
|`NewTCPSpec`|Creates a new insecure TCP connection specification using the provided address and secret.|
|`NewUnixSpec`|Creates a new insecure Unix connection specification using the provided socket and secret.|
|`NewTLSSpec`|Creates a new secure connection specification using the provided TLS key and certificate as well as the provided type, address and secret. See [Using TLS](#using-tls) for more information|

## Connections

A connection represents an IPC communication channel between two processes.

Characteristics of a Connection include:

   - The first process to call `connection.Connect()` will run as the server and the second process to call the function will run as the client.
   - Only two processes can ever use the same IPC Connection at once.
   - If the process is running as the client and the server goes away, it will continually attempt to reconnect until the server is available again.
   - When operating as a client the process will send keep alive packets at an interval **1/2** the length of the QueryTimeout parameter of the Connection in order to avoid any potential I/O timeouts.

You can create a new connection using a Connection Specification.

```go
connection := ipc.NewConnection(spec)
```

You can then connect to it using the `connection.Connect()` function.

```go
err := connection.Connect()
if err != nil {
    panic(err)
}
```

In order to reconnect in the event of a failure a process must first successfully call the `connection.Connect()` function without any errors. If you want to guarantee a process successfully connects before terminating, you should wrap the `connection.Connect()` call. After the initial call to `connection.Connect()` returns without error, all subsequent "retries" that may be required due to the server dropping connection will be automatic. See [Customizing Reconnect Behavior](#customizing-reconnect-behavior) for more information.

```go
go func() {
    var error err
    for {
        err = connection.Connect()
        if err != nil {
            fmt.Printf("connect error: %v\n", err)
            continue
        }

        break
    }
}
```

## Message Handlers

You should pass a `MessageHandler` to the `ipc.NewConnection` function. This message handler will be used to receive queries and respond with the appropriate data. In the event that you have no response you should return an empty string.

```go
func MyMessageHandler(message string) string {
    if message == "hello" {
        return "world"
    }

    return ""
}
```

## Querying the Connection

Either side of the connection can call `Query()` on their Connection object to query the other side of the tunnel. If the peer is not available, the query will return an error until it again becomes available.

```go
response, err := connection.Query("hello")
```

## Customizing Timeout

You can customize the timeout of your `Connection` object by modifying the `QueryTimeout` property. The default value is **5 seconds**. Keep Alive packets will be sent from the client to the server at an interval 1/2 that of the QueryTimeout in order to avoid any potential I/O timeouts.

```go
connection.QueryTimeout = time.Second * 3
```

## Customizing Reconnect Behavior

By default, when a process that has started as a client loses it's connection to the server it will indefinitely try to reconnect once a second until the server becomes available again.

You can configure this behavior using the `Reconnect`, `ReconnectMaxRetries`, and `ReconnectDelay` properties of the `Connection` object.

   - `Reconnect` -- When set to false the "reconnect" behavior will be entirely disabled and the connection will instead be dropped.
   - `ReconnectMaxRetries` -- After this many failed attempts to reconnect, the client will drop the connection. A `0` value indicates unlimited retries.
   - `ReconnectDelay` -- The duration to wait between each attempt to reconnect. Default value is one second.

## Using Encryption

> The encryption system that is built into this IPC system is not intended to be used for securing connections but instead for locking the availability scope of the data contained in messages to the processes involved in the IPC Connection.

By default, no encryption is enabled. You can either use the built in AES-256-GCM Encryption or implement your own `EncryptionProvider`.

### Encryption Keys

You can create a new `EncryptionKey` using the `ipc.NewEncryptionKey()` function. This function will return an error if the source of randomness fails. The resulting key will be a slice of random bytes, 256-bits long.

```go
encryptionKey, err := ipc.NewEncryptionKey()
```

You can then write this encryption key to a file using the `encryptionKey.WriteToFile()` function.

```go
encryptionKey.WriteToFile("./encryption.key")
```

You can alternately load the encryption key using the `ipc.LoadEncryptionKey()` function.

```go
encryptionKey, err := ipc.LoadEncryptionKey("./encryption.key")
```

### Default Encryption Provider

To use the default encryption provider which provides 256-bit AES-GCM encryption, use the `ipc.NewDefaultEncryptionProvider()` function.

```go
encryptionProvider := ipc.NewDefaultEncryptionProvider(encryptionKey)
ipc.SetEncryptionProvider(encryptionProvider)
```

### Custom Encryption Provider

You can implement a custom encryption provider by implementing the `EncryptionProvider` interface.

```go
type MyEncryptionProvider struct {}

func (enc MyEncryptionProvider) Encrypt(plaintext []byte) ([]byte, error) {
    // encrypt plaintext and return the ciphertext
    return plaintext, nil
}

func (enc MyEncryptionProvider) Decrypt(ciphertext []byte) ([]byte, error) {
    return ciphertext, nil
}

func main() {
    ipc.SetEncryptionProvider(MyEncryptionProvider{})
}
```

## Using TLS

To add support for TLS to your IPC Connection you can create a TLS `Spec`. This requires that you have a Certificate and Key accessible on the file-system.

1. Generate the certificate & key

   **Key**

   ```sh
   # For algorithm "RSA" ≥ 2048-bit
   $ openssl genrsa -out server.key 2048

   # For algorithm "ECDSA" ≥ secp384r1
   $ openssl ecparam -genkey -name secp384r1 -out server.key
   ```

   **Certificate**

   ```sh
   $ openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
   ```

2. Create a new `Spec` using the certificate and key.

   ```go
   spec, err := ipc.NewTLSSpec("tcp", "127.0.0.1:55412", "./server.crt", "./server.key", "some_secret")
   ```

   Once you've created the `Spec`, you can create a new IPC connection using the `ipc.NewConnection()` function.

