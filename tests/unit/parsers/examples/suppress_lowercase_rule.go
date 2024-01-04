package main

import (
    "crypto/md5"
)

func main() {
    h := md5.New() // suppress: go002
}
