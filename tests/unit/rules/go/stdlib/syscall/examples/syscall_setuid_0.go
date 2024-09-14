// level: ERROR
// start_line: 16
// end_line: 16
// start_column: 29
// end_column: 30
package main

import (
    "fmt"
    "log"
    "os"
    "syscall"
)

func main() {
    if err := syscall.Setuid(0); err != nil {
        log.Fatalf("Failed to set UID: %v", err)
    }

    fmt.Printf("Running as UID: %d\n", os.Getuid())
}
