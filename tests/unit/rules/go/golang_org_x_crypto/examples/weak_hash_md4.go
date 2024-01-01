package main

import (
    "golang.org/x/crypto/md4"
    "fmt"
)

func main() {
    h := md4.New()
    h.Write([]byte("hello world\n"))
    fmt.Printf("%x", h.Sum(nil))
}
