// level: ERROR
// start_line: 22
// end_line: 22
// start_column: 14
// end_column: 27
package main

import (
    "crypto/rc4"
    "fmt"
    "log"
)

func main() {
    // The key for RC4 must be between 1 and 256 bytes long
    key := []byte("your-secure-key")

    // The plaintext message you want to encrypt
    plaintext := []byte("Hello, world!")

    // Creating the cipher
    c, err := rc4.NewCipher(key)
    if err != nil {
        log.Fatal(err)
    }

    // Encrypting the plaintext
    ciphertext := make([]byte, len(plaintext))
    c.XORKeyStream(ciphertext, plaintext)

    fmt.Printf("Ciphertext: %x\n", ciphertext)
}
