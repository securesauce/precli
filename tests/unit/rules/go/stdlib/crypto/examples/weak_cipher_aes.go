// level: NONE
package main

import (
    "crypto/aes"
)

func main() {
    aesKey := []byte("example key 1234")

    _, err := aes.NewCipher(aesKey)
    if err != nil {
        panic(err)
    }
}
