package ipc

import (
	"log"
	"os"
)

var debugLogger *log.Logger = nil
var logQueries bool = false
var logKeepAlives bool = false

// SetDebugLogger will set the logger to use for debug messages. By
// default debug messages are not printed.
func SetDebugLogger(logger *log.Logger) {
	debugLogger = logger
}

// SetLogQueries will tell the system to log each query as it is sent
// and received to the debug log. You must set a logger using the
// SetDebugLogger function in order for queries to be logged.
func SetLogQueries(value bool) {
	logQueries = value
}

// SetLogKeepAlivePackets will tell the system to log each keep-alive
// packet as it is sent and received to the debug log. You must set
// a logger using the SetDebugLogger function in order for keep-alive
// packets to be logged.
func SetLogKeepAlivePackets(value bool) {
	logKeepAlives = value
}

func debugLog(msg string, vargs ...interface{}) {
	if debugLogger != nil {
		debugLogger.Printf(msg, vargs...)
	}
}

// This is the same default definition that the log package uses for
// standard logging
var errorLogger *log.Logger = log.New(os.Stderr, "IPC ", log.LstdFlags)

// SetErrorLogger will set the logger to use for error messages. By
// default log messages will be written to Stderr.
func SetErrorLogger(logger *log.Logger) {
	errorLogger = logger
}

func errorLog(msg string, vargs ...interface{}) {
	if errorLogger != nil {
		errorLogger.Printf(msg, vargs...)
	}
}
