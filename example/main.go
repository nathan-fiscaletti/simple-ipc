package main

import (
    ipc ".."
    "fmt"
    "time"
    "log"
    "os"
)

// Handle incoming messages and respond to them.
func handleMessage(message string) string {
    if message == "hello" {
        return "world"
    }

    return ""
}

func main() {
    debugLogger := log.New(os.Stdout, "IPC ", log.LstdFlags)
    ipc.SetDebugLogger(debugLogger)
    ipc.SetLogQueries(true)
    ipc.SetLogKeepAlivePackets(true)

    key,err := ipc.LoadEncryptionKey("./encryption_key")
    if err != nil {
        panic(err)
    }

    // Set the Encryption Provider
    ipc.SetEncryptionProvider(ipc.NewDefaultEncryptionProvider(key))

    // Create a new handle defining the socket
    spec, err := ipc.NewTLSSpec("tcp", "127.0.0.1:55412", "./server.crt", "./server.key", "secret")
    if err != nil {
        panic(err)
    }

    // Create a new Connection
    conn := ipc.NewConnection(spec, handleMessage)

    // Connect to it
    err = conn.Connect()
    if err != nil {
        fmt.Printf("connect error: %v\n", err)
        return
    }

    // You can now query the connection
    for true {
        res, err := conn.Query("hello")
        if err != nil {
            fmt.Printf("query error: %v\n", err)
        }
        if res != "" {
            fmt.Printf("query response: %v\n", res)
        }
        time.Sleep(time.Second * 10)
    }
}