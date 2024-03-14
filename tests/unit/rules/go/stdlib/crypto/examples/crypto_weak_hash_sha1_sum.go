// level: ERROR
// start_line: 15
// end_line: 15
// start_column: 22
// end_column: 30
package main

import (
    "crypto/sha1"
    "fmt"
)

func main() {
    data := []byte("This page intentionally left blank.")
    fmt.Printf("% x", sha1.Sum(data))
}
