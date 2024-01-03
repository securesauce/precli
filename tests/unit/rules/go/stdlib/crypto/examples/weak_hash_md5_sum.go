// level: ERROR
// start_line: 15
// end_line: 15
// start_column: 21
// end_column: 28
package main

import (
    "crypto/md5"
    "fmt"
)

func main() {
    data := []byte("These pretzels are making me thirsty.")
    fmt.Printf("%x", md5.Sum(data))
}
