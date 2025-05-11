// level: WARNING
// start_line: 14
// end_line: 14
// start_column: 33
// end_column: 44
package main

import (
    "log"
    "net"
)

func main() {
    ln, err := net.Listen("tcp", "[::]:8443")
    if err != nil {
        log.Fatalf("net.Listen failed on %s: %v", "[::]", err)
    }
    defer ln.Close()
}
