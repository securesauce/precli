// level: NONE
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "log"
)

func GeneratePrivateKey(bits int) (*rsa.PrivateKey) {
    privateKey, err := rsa.GenerateKey(rand.Reader, bits)
    if err != nil {
        return nil, nil
    }
    return privateKey
}

func main() {
    // Generate the RSA key
    privateKey, err := GeneratePrivateKey(2048)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    // Extract the public key from the private key
    publicKey := &privateKey.PublicKey

    // Encode the public key to PEM format
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
    if err != nil {
        log.Fatalf("Failed to marshal public key: %v", err)
    }

    publicKeyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PUBLIC KEY",
        Bytes: publicKeyBytes,
    })

    // Print the public key
    log.Println(string(publicKeyPEM))
}
