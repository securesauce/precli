package main

import (
    "crypto/md5"
)

func main() {
    h := md5.New() // suppress: GO001 GO002 GO003
}
