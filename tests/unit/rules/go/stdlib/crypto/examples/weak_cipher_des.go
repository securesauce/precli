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
