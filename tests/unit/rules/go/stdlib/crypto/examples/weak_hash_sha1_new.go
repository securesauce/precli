package main

import (
    "crypto/sha1"
    "fmt"
)

func main() {
    h := sha1.New()
    h.Write([]byte("hello world\n"))
    fmt.Printf("%x", h.Sum(nil))
}
