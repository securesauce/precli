// level: WARNING
// start_line: 25
// end_line: 25
// start_column: 14
// end_column: 24
package main

import (
    "io"
    "log"
    "net"
    "net/http"
)

func main() {
    helloHandler := func(w http.ResponseWriter, req *http.Request) {
        io.WriteString(w, "Hello, world!\n")
    }

    http.HandleFunc("/hello", helloHandler)
    ln, err := net.Listen("tcp", "127.0.0.1:8080")
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.Serve(ln, nil))
}
