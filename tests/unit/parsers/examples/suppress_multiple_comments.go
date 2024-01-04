package main

import (
    "crypto/md5"
)

func main() {
    h := md5.New() // type: ... // suppress: GO002 // noqa: E501 ; nolint:lll
}
