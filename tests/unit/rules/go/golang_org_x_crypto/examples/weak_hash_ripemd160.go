// level: ERROR
// start_line: 14
// end_line: 14
// start_column: 9
// end_column: 22
package main

import (
    "golang.org/x/crypto/ripemd160"
    "fmt"
)

func main() {
    h := ripemd160.New()
    h.Write([]byte("hello world\n"))
    fmt.Printf("%x", h.Sum(nil))
}
