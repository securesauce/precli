package main

import (
    "crypto/md5"
)

func main() {
    // suppress: GO002
    h := md5.New()
}
