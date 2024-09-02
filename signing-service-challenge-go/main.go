package main

import (
	"log"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

const (
	ListenAddress = ":8080"
)

func getSignatureService() (*domain.SignatureService, error) {
	algorithms := map[string]domain.Algorithm[domain.KeyPair]{
		"RSA": crypto.RSAAlgorithm{},
	}

	return domain.NewSignatureService(algorithms)
}

func main() {
	signatureService, err := getSignatureService()
	if err != nil {
		log.Fatalf("Could not get SignatureService: %v\n", err)
	}

	server, err := api.NewServer(ListenAddress, signatureService)
	if err != nil {
		log.Fatalf("Could not create NewServer: %v\n", err)
	}

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
