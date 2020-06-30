package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
	ethkms "quorumcontrol.com/eth-kms"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	awsSession := session.Must(session.NewSession())
	kmsClient := kms.New(awsSession)

	s, err := ethkms.CreateKey(ctx, kmsClient)
	if err != nil {
		panic(err)
	}
	// save s.KeyID for future invocations like so:
	// s := ethkms.NewSignerFromID(keyID)

	digest := crypto.Keccak256([]byte("test"))

	sig, err := s.Sign(ctx, digest)
	if err != nil {
		panic(err)
	}

	fmt.Printf("signature: %s", base64.StdEncoding.EncodeToString(sig))
}
