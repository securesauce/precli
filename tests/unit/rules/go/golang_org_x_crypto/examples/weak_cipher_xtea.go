// level: ERROR
// start_line: 17
// end_line: 17
// start_column: 14
// end_column: 28
package main

import (
    "log"

    "golang.org/x/crypto/xtea"
)

func main() {
    key := []byte("examplekey123456")

    _, err := xtea.NewCipher(key)
    if err != nil {
        log.Fatalf("Failed to create cipher: %v", err)
    }
}
