# ETH-KMS

This is a small golang library for using AWS KMS as an HSM for ethereum. It wraps the AWS KMS library so that it returns eth-compatible signatures. 

## Usage

See the tests (which, unfortunately cannot be run without modifying the variables at the top and supplying your own AWS credentials).

```golang
package main

import(
    "fmt"
    "quorumcontrol.com/eth-kms"
	"github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/kms"
    "github.com/ethereum/go-ethereum/crypto"
)

func main() {
    awsSession := session.Must(session.NewSession())
    kmsClient := kms.New(awsSession)
    
	s, err := CreateKey(ctx, kmsClient)
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

```

## Tests


I recommend using aws-vault for credential management. I run the tests like this:

```
aws-vault exec myProfileName -- go test .
```

You'll need to modify the ethkms_test.go file to reflect your own actual values.