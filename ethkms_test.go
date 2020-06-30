package ethkms

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyID = "88c8e79f-262f-4893-a02f-5ecfdbee65a3"
const testKeyPubBase64 = "BD6zglZaze8Q61HsI8+QbxcRwTKmlfW3hSFvbCUJYg2tHShw3wxyLG4nVuVwDVX1ZN38C0lVI/vA/y0yS40ERds="

var testKeyPub []byte

func init() {
	pub, err := base64.StdEncoding.DecodeString(testKeyPubBase64)
	if err != nil {
		panic(err)
	}
	testKeyPub = pub
}

func TestGetPublicKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	awsSession := session.Must(session.NewSession())
	kmsClient := kms.New(awsSession)

	signer := NewSignerFromID(kmsClient, testKeyID)
	pubKey, err := signer.PublicKey(ctx)
	require.Nil(t, err)
	assert.Equal(t, crypto.FromECDSAPub(pubKey), testKeyPub)
}

func TestCreateKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	awsSession := session.Must(session.NewSession())
	kmsClient := kms.New(awsSession)

	s, err := CreateKey(ctx, kmsClient)
	require.Nil(t, err)
	require.NotNil(t, s.KeyID)

	_, err = kmsClient.ScheduleKeyDeletionWithContext(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               &s.KeyID,
		PendingWindowInDays: aws.Int64(7),
	})
	require.Nil(t, err)
}

func TestSign(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	awsSession := session.Must(session.NewSession())
	kmsClient := kms.New(awsSession)
	s := NewSignerFromID(kmsClient, testKeyID)
	digest := crypto.Keccak256([]byte("test"))

	sig, err := s.Sign(ctx, digest)
	require.Nil(t, err)
	assert.Len(t, sig, 65)

	recovered, err := crypto.Ecrecover(digest, sig)
	require.Nil(t, err)
	assert.Equal(t, testKeyPub, recovered)
}
