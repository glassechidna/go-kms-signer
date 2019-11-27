package kmsagent

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/glassechidna/go-kms-signer/kmssigner"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type kmsagent struct {
	signers []*kmssigner.Signer
}

func New(signers []*kmssigner.Signer) (agent.Agent, error) {
	return &kmsagent{signers: signers}, nil
}

func (k *kmsagent) List() ([]*agent.Key, error) {
	var keys []*agent.Key

	for _, signer := range k.signers {
		sshsign, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return nil, err
		}

		pubkey := sshsign.PublicKey()
		keys = append(keys, &agent.Key{
			Format:  pubkey.Type(),
			Blob:    pubkey.Marshal(),
			Comment: signer.KeyId(),
		})
	}

	return keys, nil
}

func (k *kmsagent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	for _, signer := range k.signers {
		sshsign, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return nil, err
		}

		pubkey := sshsign.PublicKey()
		if !bytes.Equal(pubkey.Marshal(), key.Marshal()) {
			continue
		}

		signature, err := sshsign.Sign(nil, data)
		spew.Dump(signature, err)
		return signature, err
	}

	return nil, errors.New("nope")
}

func (k *kmsagent) Add(key agent.AddedKey) error {
	panic("implement me")
}

func (k *kmsagent) Remove(key ssh.PublicKey) error {
	panic("implement me")
}

func (k *kmsagent) RemoveAll() error {
	panic("implement me")
}

func (k *kmsagent) Lock(passphrase []byte) error {
	panic("implement me")
}

func (k *kmsagent) Unlock(passphrase []byte) error {
	panic("implement me")
}

func (k *kmsagent) Signers() ([]ssh.Signer, error) {
	var sshSigners []ssh.Signer

	for _, signer := range k.signers {
		sshsign, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return nil, err
		}

		sshSigners = append(sshSigners, sshsign)
	}

	return sshSigners, nil
}

func (k *kmsagent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	for _, signer := range k.signers {
		sshsign, err := ssh.NewSignerFromSigner(signer)
		if err != nil {
			return nil, err
		}

		pubkey := sshsign.PublicKey()
		if !bytes.Equal(pubkey.Marshal(), key.Marshal()) {
			continue
		}

		var algorithm string
		switch flags {
		case agent.SignatureFlagRsaSha256:
			algorithm = ssh.SigAlgoRSASHA2256
		case agent.SignatureFlagRsaSha512:
			algorithm = ssh.SigAlgoRSASHA2512
		default:
			return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
		}

		if algoSigner, ok := sshsign.(ssh.AlgorithmSigner); ok {
			signature, err := algoSigner.SignWithAlgorithm(nil, data, algorithm)
			spew.Dump(signature, err)
			return signature, err
		}
	}

	return nil, errors.New("nope")
}

func (k *kmsagent) Extension(extensionType string, contents []byte) ([]byte, error) {
	panic("implement me")
}
