// level: ERROR
// start_line: 17
// end_line: 17
// start_column: 14
// end_column: 37
package main

import (
    "log"

    "golang.org/x/crypto/tea"
)

func main() {
    key := []byte("examplekey123456")

    _, err := tea.NewCipherWithRounds(key, 64)
    if err != nil {
        log.Fatalf("Failed to create cipher: %v", err)
    }
}
