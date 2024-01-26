// level: ERROR
// start_line: 14
// end_line: 14
// start_column: 9
// end_column: 17
package main

import (
    "crypto/sha1"
    "fmt"
)

func main() {
    h := sha1.New()
    h.Write([]byte("hello world\n"))
    fmt.Printf("%x", h.Sum(nil))
}
