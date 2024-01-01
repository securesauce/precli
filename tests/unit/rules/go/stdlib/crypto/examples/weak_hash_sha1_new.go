// level: ERROR
// start_line: 9
// end_line: 9
// start_column: 38
// end_column: 41
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
