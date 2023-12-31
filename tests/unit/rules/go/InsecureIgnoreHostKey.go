package main

import (
    "fmt"
    "golang.org/x/crypto/ssh"
    "net"
)

func main() {
    // SSH client configuration with InsecureIgnoreHostKey
    config := &ssh.ClientConfig{
        User: "username",
        Auth: []ssh.AuthMethod{
            ssh.Password("password"),
        },
        // InsecureIgnoreHostKey returns a function that can be used for
        // ClientConfig.HostKeyCallback to accept any host key. It should not
        // be used for production code.
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

    // Define the SSH server address
    serverAddress := "example.com:22"

    // Establish a connection to the SSH server
    conn, err := ssh.Dial("tcp", serverAddress, config)
    if err != nil {
        fmt.Println("Failed to dial:", err)
        return
    }
    defer conn.Close()

    // Perform operations using the connection...
    // For example, creating a session
    session, err := conn.NewSession()
    if err != nil {
        fmt.Println("Failed to create session:", err)
        return
    }
    defer session.Close()

    // Execute a command
    output, err := session.CombinedOutput("ls -l")
    if err != nil {
        fmt.Println("Failed to execute command:", err)
        return
    }

    fmt.Println(string(output))
}
