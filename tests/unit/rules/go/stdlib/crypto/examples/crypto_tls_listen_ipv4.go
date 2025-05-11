// level: WARNING
// start_line: 23
// end_line: 23
// start_column: 33
// end_column: 47
package main

import (
    "crypto/tls"
    "log"
)

func main() {
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatalf("failed to load key pair: %v", err)
    }

    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    ln, err := tls.Listen("tcp", "0.0.0.0:8443", config)
    if err != nil {
        log.Fatalf("tls.Listen failed on %s: %v", "0.0.0.0", err)
    }
    defer ln.Close()
}
