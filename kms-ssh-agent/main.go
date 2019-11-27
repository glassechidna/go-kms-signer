package main

import (
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/glassechidna/go-kms-signer/kms-ssh-agent/kmsagent"
	"github.com/glassechidna/go-kms-signer/kms-ssh-agent/socket"
	"github.com/glassechidna/go-kms-signer/kmssigner"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"text/template"
)

func main() {
	if len(os.Args) != 2 {
		exe, _ := os.Executable()
		fmt.Fprintf(os.Stderr, "usage: %s install|agent\n", exe)
		os.Exit(1)
	}

	sess := session.Must(session.NewSession())
	api := kms.New(sess)

	if os.Args[1] == "install" {
		err := install(api)
		if err != nil {
			log.Fatalf("%+v\n", err)
		}
	} else if os.Args[1] == "agent" {
		keyId := os.Getenv("KeyId")
		err := serve(api, keyId)
		if err != nil {
			log.Fatalf("%+v\n", err)
		}
	} else {
		panic("Unrecognised command")
	}
}

func serve(api kmsiface.KMSAPI, keyId string) error {
	signer := kmssigner.New(api, keyId, kmssigner.ModeRsaPkcs1v15)

	lis, err := socket.Listener("agentSocket")
	if err != nil {
		panic(err)
	}

	kmsag, err := kmsagent.New([]*kmssigner.Signer{signer})
	if err != nil {
		panic(err)
	}

	for {
		conn, err := lis.Accept()
		if err != nil {
			panic(err)
		}

		err = agent.ServeAgent(kmsag, conn)
		if err != nil && err != io.EOF {
			panic(err)
		}
	}
}

func install(api kmsiface.KMSAPI) error {
	u, err := user.Current()
	if err != nil {
		return errors.WithStack(err)
	}

	create, err := api.CreateKey(&kms.CreateKeyInput{
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecRsa2048),
		Description:           aws.String(fmt.Sprintf("kms-ssh-agent for %s", u.Username)),
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("created-by"),
				TagValue: aws.String("kms-ssh-agent"),
			},
		},
	})
	if err != nil {
		return errors.WithStack(err)
	}

	keyArn := *create.KeyMetadata.Arn
	fmt.Println(keyArn)
	fmt.Printf("* Created KMS key with ARN: %s\n", keyArn)

	plistTemplate, err := template.New("").Parse(`
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.glassechidna.kms-ssh-agent</string>
        <key>ProgramArguments</key>
        <array>
            <string>{{ .ExePath }}</string>
            <string>agent</string>
        </array>
        <key>EnvironmentVariables</key>
        <dict>
            <key>KeyId</key>
            <string>{{ .KeyId }}</string>
        </dict>
        <key>Sockets</key>
        <dict>
            <key>agentSocket</key>
            <dict>
                <key>SockFamily</key>
                <string>Unix</string>
                <key>SockPathMode</key>
                <integer>448</integer>
                <key>SockPathName</key>
                <string>{{ .SocketPath }}</string>
                <key>SockType</key>
                <string>Stream</string>
            </dict>
        </dict>
    </dict>
</plist>
`[1:])
	if err != nil {
		return errors.WithStack(err)
	}

	buf := &bytes.Buffer{}
	socketPath := filepath.Join(u.HomeDir, ".ssh", "kms-ssh-agent.sock")
	exePath, err := os.Executable()
	if err != nil {
		return errors.WithStack(err)
	}

	err = plistTemplate.Execute(buf, map[string]string{
		"SocketPath": socketPath,
		"ExePath":    exePath,
		"KeyId":      keyArn,
	})
	if err != nil {
		return errors.WithStack(err)
	}

	plistPath := filepath.Join(u.HomeDir, "Library", "LaunchAgents", "com.glassechidna.kms-ssh-agent.plist")
	err = ioutil.WriteFile(plistPath, buf.Bytes(), 0644)
	if err != nil {
		return errors.WithStack(err)
	}

	fmt.Printf("* Wrote launch agent plist to %s\n", plistPath)

	sshConfigPath := filepath.Join(u.HomeDir, ".ssh", "config")
	sshConfig, err := os.OpenFile(sshConfigPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = sshConfig.WriteString(fmt.Sprintf(`
Host *
  IdentityAgent %s
`, socketPath))
	if err != nil {
		return errors.WithStack(err)
	}

	err = sshConfig.Close()
	if err != nil {
		return errors.WithStack(err)
	}

	fmt.Printf("* Added IdentityAgent config to %s\n", sshConfigPath)

	pubresp, err := api.GetPublicKey(&kms.GetPublicKeyInput{KeyId: &keyArn})
	if err != nil {
		return errors.WithStack(err)
	}

	key, err := kmssigner.ParseCryptoKey(pubresp)
	if err != nil {
		return errors.WithStack(err)
	}

	sshkey, err := ssh.NewPublicKey(key)
	if err != nil {
		return errors.WithStack(err)
	}

	authorized := ssh.MarshalAuthorizedKey(sshkey)
	fmt.Printf("* Now you can add the following SSH public key to .ssh/authorized_keys on hosts you want to SSH into:\n\n%s", authorized)

	fmt.Printf(`
If you want to uninstall, follow these steps:

  * Delete %s
  * Delete %s
  * Remove the IdentityAgent at the bottom of %s
  * Delete the KMS key with ARN %s
`, exePath, socketPath, sshConfigPath, keyArn)

	return nil
}
