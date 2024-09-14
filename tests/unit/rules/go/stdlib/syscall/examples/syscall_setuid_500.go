// level: NONE
package main

import (
    "fmt"
    "log"
    "os"
    "syscall"
)

func main() {
    if err := syscall.Setuid(500); err != nil {
        log.Fatalf("Failed to set UID: %v", err)
    }

    fmt.Printf("Running as UID: %d\n", os.Getuid())
}
