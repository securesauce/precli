// level: NONE
package main

import (
    "crypto/dsa"
    "crypto/rand"
    "fmt"
    "log"
    "math/big"
)

func main() {
    // Define DSA parameters
    var params dsa.Parameters

    // Generate DSA parameters; here we choose a 1024-bit key size
    if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256); err != nil {
        log.Fatalf("Failed to generate DSA parameters: %v", err)
    }

    // Generate DSA keys
    privateKey := new(dsa.PrivateKey)
    privateKey.PublicKey.Parameters = params
    if err := dsa.GenerateKey(privateKey, rand.Reader); err != nil {
        log.Fatalf("Failed to generate DSA key: %v", err)
    }

    // Extract the public key
    publicKey := privateKey.PublicKey

    // Print the public key
    fmt.Printf("Public Key:\n P:%s\n Q:%s\n G:%s\n Y:%s\n",
        publicKey.P.String(), publicKey.Q.String(), publicKey.G.String(), publicKey.Y.String())

    // Print the private key
    fmt.Printf("Private Key:\n X:%s\n", privateKey.X.String())
}
