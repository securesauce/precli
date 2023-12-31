package main

import (
    "crypto/md5"
    "fmt"
)

func main() {
    h := md5.New()
    h.Write([]byte("hello world\n"))
    fmt.Printf("%x", h.Sum(nil))
}
