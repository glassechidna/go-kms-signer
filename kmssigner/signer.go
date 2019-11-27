package kmssigner

import (
	"crypto"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"io"
)

type Signer struct {
	api    kmsiface.KMSAPI
	keyId  string
	mode   Mode
	public crypto.PublicKey
}

func New(api kmsiface.KMSAPI, keyId string, mode Mode) *Signer {
	return &Signer{
		api:   api,
		keyId: keyId,
		mode:  mode,
	}
}

func (s *Signer) KeyId() string {
	return s.keyId
}

func (s *Signer) RetrievePublicKey() (crypto.PublicKey, error) {
	resp, err := s.api.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: &s.keyId,
	})
	if err != nil {
		return nil, err
	}

	s.public, err = ParseCryptoKey(resp)
	if err != nil {
		return nil, err
	}

	return s.public, nil
}

func (s *Signer) Public() crypto.PublicKey {
	if s.public != nil {
		return s.public
	}

	key, err := s.RetrievePublicKey()
	if err != nil {
		panic(err)
	}

	return key
}

var hashMap = map[Mode]map[crypto.Hash]string{
	ModeRsaPss: {
		crypto.SHA256: kms.SigningAlgorithmSpecRsassaPssSha256,
		crypto.SHA384: kms.SigningAlgorithmSpecRsassaPssSha384,
		crypto.SHA512: kms.SigningAlgorithmSpecRsassaPssSha512,
	},
	ModeRsaPkcs1v15: {
		crypto.SHA256: kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
		crypto.SHA384: kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384,
		crypto.SHA512: kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512,
	},
	ModeEcdsa: {
		crypto.SHA256: kms.SigningAlgorithmSpecEcdsaSha256,
		crypto.SHA384: kms.SigningAlgorithmSpecEcdsaSha384,
		crypto.SHA512: kms.SigningAlgorithmSpecEcdsaSha512,
	},
}

type Mode string

const (
	ModeRsa         Mode = "rsa"
	ModeRsaPss      Mode = "pss"
	ModeRsaPkcs1v15 Mode = "pkcs1v15"
	ModeEcdsa       Mode = "ecdsa"
)

func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	mode := s.mode
	//if mode == ModeRsa {
	//	if pss, ok := opts.(*rsa.PSSOptions); ok {
	//		mode = ModeRsaPss
	//
	//		if pss.Hash != 0 {
	//
	//		} else if pss.SaltLength == rsa.PSSSaltLengthEqualsHash {
	//
	//		}
	//	}
	//}

	inner := hashMap[mode]
	if inner == nil {
		return nil, errors.New("oh no")
	}

	algorithm := inner[opts.HashFunc()]
	if algorithm == "" {
		return nil, errors.New("oh no again")
	}

	resp, err := s.api.Sign(&kms.SignInput{
		KeyId:            &s.keyId,
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: &algorithm,
	})
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}
