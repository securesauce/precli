// level: ERROR
// start_line: 14
// end_line: 14
// start_column: 9
// end_column: 16
package main

import (
    "crypto/md5"
    "fmt"
)

func main() {
    h := md5.New()
    h.Write([]byte("hello world\n"))
    fmt.Printf("%x", h.Sum(nil))
}
