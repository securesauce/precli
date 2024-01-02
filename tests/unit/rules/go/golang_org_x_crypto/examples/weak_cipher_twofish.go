// level: ERROR
// start_line: 35
// end_line: 35
// start_column: 18
// end_column: 35
package main

import (
    "crypto/cipher"
    "encoding/hex"
    "fmt"
    "golang.org/x/crypto/twofish"
    "log"
)

// pkcs7Pad pads the plaintext to be a multiple of the block size
func pkcs7Pad(plaintext []byte, blockSize int) []byte {
    padding := blockSize - len(plaintext)%blockSize
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(plaintext, padtext...)
}

// pkcs7Unpad removes the padding from the plaintext
func pkcs7Unpad(plaintext []byte) []byte {
    length := len(plaintext)
    padLen := int(plaintext[length-1])
    return plaintext[:(length - padLen)]
}

func main() {
    // Twofish key (can be 16, 24, or 32 bytes)
    key := []byte("examplekey123456") // 16 bytes for a 128-bit key

    // Create a new Twofish cipher block with the key
    block, err := twofish.NewCipher(key)
    if err != nil {
        log.Fatalf("Failed to create cipher: %v", err)
    }

    // The plaintext that needs to be encrypted
    plaintext := []byte("Hello, Twofish!")

    // Pad plaintext to be a multiple of the block size
    paddedPlaintext := pkcs7Pad(plaintext, twofish.BlockSize)

    ciphertext := make([]byte, len(paddedPlaintext))
    for i := 0; i < len(paddedPlaintext); i += twofish.BlockSize {
        block.Encrypt(ciphertext[i:i+twofish.BlockSize], paddedPlaintext[i:i+twofish.BlockSize])
    }

    fmt.Printf("Ciphertext: %x\n", ciphertext)

    // Decrypting the ciphertext
    decrypted := make([]byte, len(ciphertext))
    for i := 0; i < len(ciphertext); i += twofish.BlockSize {
        block.Decrypt(decrypted[i:i+twofish.BlockSize], ciphertext[i:i+twofish.BlockSize])
    }

    // Remove padding
    decrypted = pkcs7Unpad(decrypted)

    fmt.Printf("Decrypted: %s\n", decrypted)
}
