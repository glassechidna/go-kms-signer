package kmssigner_test

import (
	"crypto"
	"crypto/sha256"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/davecgh/go-spew/spew"
	"github.com/glassechidna/go-kms-signer/kmssigner"
	"os"
	"testing"
)

func TestSigner_Public(t *testing.T) {
	os.Setenv("AWS_REGION", "ap-southeast-2")
	sess := session.Must(session.NewSession())
	api := kms.New(sess)
	s := kmssigner.New(
		api,
		"arn:aws:kms:ap-southeast-2:607481581596:key/22123302-1e5b-4222-9827-5b338a770dfc",
		kmssigner.ModeRsaPkcs1v15,
	)

	pk := s.Public()
	spew.Dump(pk)

	h := sha256.New()
	h.Write([]byte("hello world"))
	sum := h.Sum(nil)

	signed, err := s.Sign(nil, sum, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	spew.Dump(signed)
}
