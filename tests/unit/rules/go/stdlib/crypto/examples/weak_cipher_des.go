// level: ERROR
// start_line: 19
// end_line: 19
// start_column: 38
// end_column: 41
package main

import (
    "crypto/des"
)

func main() {
    ede2Key := []byte("example key 1234")

    var tripleDESKey []byte
    tripleDESKey = append(tripleDESKey, ede2Key[:16]...)
    tripleDESKey = append(tripleDESKey, ede2Key[:8]...)

    _, err := des.NewTripleDESCipher(tripleDESKey)
    if err != nil {
        panic(err)
    }
}
