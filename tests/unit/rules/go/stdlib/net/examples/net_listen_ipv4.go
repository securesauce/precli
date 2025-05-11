// level: WARNING
// start_line: 14
// end_line: 14
// start_column: 33
// end_column: 47
package main

import (
    "log"
    "net"
)

func main() {
    ln, err := net.Listen("tcp", "0.0.0.0:8443")
    if err != nil {
        log.Fatalf("net.Listen failed on %s: %v", "0.0.0.0", err)
    }
    defer ln.Close()
}
