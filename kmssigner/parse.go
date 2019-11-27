package kmssigner

import (
	"crypto"
	"crypto/x509"
	"errors"
	"github.com/aws/aws-sdk-go/service/kms"
)

func ParseCryptoKey(msg *kms.GetPublicKeyOutput) (crypto.PublicKey, error) {
	keybytes := msg.PublicKey

	switch *msg.CustomerMasterKeySpec {
	case kms.CustomerMasterKeySpecRsa2048, kms.CustomerMasterKeySpecRsa3072, kms.CustomerMasterKeySpecRsa4096:
		return x509.ParsePKIXPublicKey(keybytes)

	case kms.CustomerMasterKeySpecEccNistP256, kms.CustomerMasterKeySpecEccNistP384, kms.CustomerMasterKeySpecEccNistP521, kms.CustomerMasterKeySpecEccSecgP256k1:
		return x509.ParseECPrivateKey(keybytes)

	default:
		return nil, errors.New("unknown key type")
	}
}
