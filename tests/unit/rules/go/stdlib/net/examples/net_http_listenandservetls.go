// level: WARNING
// start_line: 20
// end_line: 20
// start_column: 14
// end_column: 36
package main

import (
    "io"
    "log"
    "net/http"
)

func main() {
    helloHandler := func(w http.ResponseWriter, req *http.Request) {
        io.WriteString(w, "Hello, world!\n")
    }

    http.HandleFunc("/hello", helloHandler)
    log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil))
}
