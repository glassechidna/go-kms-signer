# `go-kms-signer`

## Why?

Because we can. And it's #pre:invent madness season.

## What

Two things (right now):

### `kmssigner`

This is a Go package that implements the crypto.Signer interface
and allows you to cryptographically sign digests **without the private key ever
being in memory**, powered by the new [KMS asymmetric APIs][kms-asym].

[kms-asym]: https://aws.amazon.com/blogs/security/digital-signing-asymmetric-keys-aws-kms/

You can do all sorts of amusing things with this, like:

* An HTTPS web server that can terminate TLS traffic without ever having access
  to its own private key.
* An SSH keypair that can't be stolen.

### `kms-ssh-agent`

Expanding on that previous point, maybe you want to use SSH to log into systems
and having a private key in `~/.ssh/id_rsa` makes you feel uncomfortable for some
reason. Why not entrust that private key to AWS KMS? Now you can!

Once you've downloaded `kms-ssh-agent`, you can run:

    # this will: 
    #   * create a new RSA 2048 KMS key
    #   * set up a socket-activated ssh agent daemon listening at ~/.ssh/kms-ssh-agent.sock
    #   * configure your ~/.ssh/config to use this unix socket as your IdentityAgent
    #   * print out the ssh public key for pasting into .ssh/authorized_keys on servers
    ./kms-ssh-agent install
    
    # this will:
    #   * magically ssh into your server using the power of KMS.
    ssh ec2-user@<ip>
  
## Should I use this?

_This_, specifically? Probably not. The KMS asymmetric crypto APIs? Definitely, they're
very cool.

## TODO

* Maybe a KMS-powered GPG agent because it would be amusing
* A super-duper secure HTTPS server with certificates issued by LetsEncrypt
  and private keys stored in KMS.
* systemd socket activation for Linux
* Implement better support for RSA PSS - whatever that is.
* Consider what I'm doing with my life
