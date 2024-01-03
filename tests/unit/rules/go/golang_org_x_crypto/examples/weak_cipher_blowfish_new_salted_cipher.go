// level: ERROR
// start_line: 18
// end_line: 18
// start_column: 14
// end_column: 38
package main

import (
    "log"

    "golang.org/x/crypto/blowfish"
)

func main() {
    key := []byte("examplekey123456")
    salt := []byte("1234567890abcdef")

    _, err := blowfish.NewSaltedCipher(key, salt)
    if err != nil {
        log.Fatalf("Failed to create cipher: %v", err)
    }
}
