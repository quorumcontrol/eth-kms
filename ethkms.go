package ethkms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/ethereum/go-ethereum/crypto"
)

// Signer is a wrapper around a KMS instance that supports ethereum-style signatures
type Signer struct {
	kms       kmsiface.KMSAPI
	KeyID     string
	publicKey *ecdsa.PublicKey
}

// CreateKey returns a signer with a KeyID populated, save that KeyID to reconstruct
// a signer using the same id. CreateKey takes care of using the correct ethereum-style
// algorithms, curves, etc for you.
func CreateKey(ctx context.Context, kmsCli kmsiface.KMSAPI) (*Signer, error) {
	resp, err := kmsCli.CreateKeyWithContext(ctx, &kms.CreateKeyInput{
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecEccSecgP256k1),
	})
	if err != nil {
		return nil, fmt.Errorf("error creating key: %w", err)
	}
	return &Signer{
		kms:   kmsCli,
		KeyID: *resp.KeyMetadata.KeyId,
	}, nil
}

// subjectPublicKeyInfo is an ASN.1 encoded Subject Public Key Info, defined here:
// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// NewSignerFromID returns a signer pre-populated with the keyID and the kmsCli
func NewSignerFromID(kmsCli kmsiface.KMSAPI, keyID string) *Signer {
	return &Signer{
		kms:   kmsCli,
		KeyID: keyID,
	}
}

// PublicKey returns the public key from the KMS (this will result in a network request before cacheing the results)
func (s *Signer) PublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	if s.publicKey != nil {
		return s.publicKey, nil
	}
	k, err := s.fetchPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting key: %w", err)
	}
	s.publicKey = k
	return k, nil
}

// Sign accepts a sha256 digest and returns the ethereum-compatible signature
// AWS only returns the r & s values of a signature, this will take those values
// and calculate the v value by trying both a 0 and a 1 and returning the first
// one that returns the actual public key
func (s *Signer) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	resp, err := s.kms.SignWithContext(ctx, &kms.SignInput{
		KeyId:            &s.KeyID,
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecEcdsaSha256),
	})
	if err != nil {
		return nil, fmt.Errorf("error signing: %v", err)
	}

	var rAndS []*big.Int
	rest, err := asn1.Unmarshal(resp.Signature, &rAndS)
	if err != nil || len(rest) > 0 {
		return nil, fmt.Errorf("error unmarshaling signature: %w", err)
	}

	pubKey, err := s.PublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("error fetching public key: %w", err)
	}

	pubKeyBytes := crypto.FromECDSAPub(pubKey)

	sigWithoutRecover := append(rAndS[0].Bytes(), rAndS[1].Bytes()...)

	for i := 0; i <= 1; i++ {
		sigWithRecover := append(sigWithoutRecover, byte(i))
		recovered, err := crypto.Ecrecover(digest, sigWithRecover)
		if err != nil {
			return nil, fmt.Errorf("error attempting recovery: %w", err)
		}
		if bytes.Equal(pubKeyBytes, recovered) {
			return sigWithRecover, nil
		}
	}

	return nil, fmt.Errorf("could not find correct recovery sig: %v", err)
}

func (s *Signer) fetchPublicKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	if s.KeyID == "" {
		return nil, errors.New("unknown key")
	}
	out, err := s.kms.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(s.KeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("error getting public key: %w", err)
	}

	var pub subjectPublicKeyInfo
	restPub, err := asn1.Unmarshal(out.PublicKey, &pub)
	if err != nil || len(restPub) > 0 {
		return nil, fmt.Errorf("error unmarshaling public key: %w", err)
	}
	return crypto.UnmarshalPubkey(pub.PublicKey.Bytes)
}
