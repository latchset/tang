# Tang

## Welcome to Tang!
Tang is a server for binding data to network presence.

This sounds fancy, but the concept is simple. You have some data, but you only
want it to be available when the system containing the data is on a certain,
usually secure, network. This is where Tang comes in.

First, the client gets a list of the Tang server's advertised asymmetric keys.
This can happen online by a simple HTTP GET. Alternatively, since the keys are
asymmetric, the public key list can be distributed out of band.

Second, the client uses one of these public keys to generate a unique,
cryptographically strong encryption key. The data is then encrypted using this
key. Once the data is encrypted, the key is discarded. Some small metadata is
produced as part of this operation which the client should store in a
convenient location. This process of encrypting data is the provisioning step.

Third, when the client is ready to access its data, it simply loads the
metadata produced in the provisioning step and performs an HTTP POST in order
to recover the encryption key. This process is the recovery step.

#### Tang Versus Key Escrow: Ease of Use and Simple Security

Tang provides an easy and secure alternative to key escrows.

Before Tang, automated decryption usually took the form of generating a key,
encrypting data with it and then storing the key in a remote server. This
remote server is called a key escrow.

The concept of key escrow is simple, but managing it can be complex.

Key escrows are stateful by nature. And since they store live data (the
encryption keys), they must be surrounded by a sophisticated backup policy.
This backup policy also needs to be carefully secured, otherwise improper
access to the keys could be obtained. Further, since keys are transferred over
the wire, typically SSL/TLS is used. SSL/TLS is a large protocol, with a
corresponding large attack surface; resulting in attacks like Heartbleed. Even
further, escrows require a comprehensive authentication policy. Without this
any user on the network can fetch any key. Often this is deployed using X.509
certificates, which bring their own complexity.

In contrast, Tang is stateless and doesn't require TLS or authentication. Tang
also has limited knowledge. Unlike escrows, where the server has knowledge of
every key ever used, Tang never sees a single client key. Tang never gains any
identifying information from the client.

|                |   Escrow   |   Tang   |
|---------------:|:----------:|:--------:|
|      Stateless |     No     |    Yes   |
|          X.509 |  Required  | Optional |
|        SSL/TLS |  Required  | Optional |
| Authentication |  Required  | Optional |
|      Anonymous |     No     |    Yes   |

## Getting Started
### Dependencies

Tang requires a few other software libraries:

1. http-parser - https://github.com/nodejs/http-parser
2. systemd - https://github.com/systemd/systemd
3. jose >= 8 - https://github.com/latchset/jose

#### Fedora

Tang is packaged for Fedora. This package should be used as it contains
additional settings (such as SETGID directories) out of the box. To install it:

    $ sudo dnf install tang

Fedora also packages the nagios plugin for monitoring the Tang server:

    $ sudo dnf install tang-nagios

If you really want to build from source on Fedora, you will need the following
packages:

1. http-parser - ``http-parser-devel``
2. systemd - ``systemd``
3. jose >= 8 - ``jose``, ``libjose-devel``
4. curl - curl (only needed for running tests)

### Building and Installing from Source

Building Tang is fairly straightforward:

    $ autoreconf -if
    $ ./configure --prefix=/usr --libdir=/usr/lib64
    $ make
    $ sudo make install

You can even run the tests if you'd like:

    $ make check

### Server Enablement

Once installed, starting a Tang server is simple:

    $ sudo systemctl enable tangd.socket --now

This command will enable Tang for startup at boot and will additionally start
it immediately. During the first startup, your initial signing and exchange
keys will be generated automatically.

That's it! You're up and running!

### Key Rotation

It is important to periodically rotate your keys. This is a simple three step
process. In this example, we will rotate only a signing key; but all key types
should be rotated.

First, generate the new keys (see jose documentation for more options):

    $ sudo jose jwk gen -i '{"alg":"ES512"}' -o /var/db/tang/newsig.jwk
    $ sudo jose jwk gen -i '{"alg":"ECMR"}' -o /var/db/tang/newexc.jwk

Second, disable advertisement of the previous key:

    $ sudo mv /var/db/tang/oldsig.jwk /var/db/tang/.oldsig.jwk

Third, after some reasonable period of time you may delete the old keys. You
should only delete the old keys when you are sure that no client require them
anymore. You have been warned.

## Tang Protocol

Tang relies on the JSON Object Signing and Encryption (JOSE) standards.
All messages in the Tang protocol are valid JOSE objects. Because of this,
you can easily write your own trivial Tang clients using off-the-shelf JOSE
libraries and/or command-line utilities. However, this also implies that
comprehending the Tang protocol will require a basic understanding of JOSE
objects.

All Tang messages are transported using a simple HTTP REST API.

| Method   | Path         | Operation                                     |
|---------:|:-------------|:----------------------------------------------|
|    `GET` | `/adv`       | Fetch public keys                             |
|    `GET` | `/adv/{kid}` | Fetch public keys using specified signing key |
|   `POST` | `/rec/{kid}` | Perform recovery using specified exchange key |

### Advertisement

The advertisement reply message contains a JWS-signed JWKSet.

The (outer) JWS contains signatures using all of the advertised signing JWKs.

The (inner) JWKSet contains all of the advertised public JWKs. This includes
all advertised signing, encryption and exchange JWKs.

Typically, a client will perform "Trust On First Use" in order to trust the
server's advertisement. However, once the client trusts at least one signing
JWK, further advertisements can be requested using that signing JWK. This
allows clients to upgrade their chain of trust.

### Binding

Tang implements the McCallum-Relyea exchange as described below.

The basic idea of a McCallum-Relyea exchange is that the client performs an
ECDH key exchange in order to produce the binding key, but then discards its
own private key so that the Tang server is the only party that can reconstitute
the binding key. Additionally, a third, ephemeral key is used to blind the
client's public key and the binding key so that only the client can unblind
them. In short, blinding makes the recovery request and response
indistinguishable from random to both eavesdroppers and the Tang server itself.

The POST request and reply bodies are JWK objects.

#### Provisioning

The client selects one of the Tang server's exchange keys (`sJWK`; identified
by the use of `deriveKey` in the `sJWK`'s `key_ops` attribute). The client
generates a new (random) JWK (`cJWK`). The client performs its half of a
standard ECDH exchange producing `dJWK` which it uses to encrypt the data.
Afterwards, it discards `dJWK` and the private key from `cJWK`.

The client then stores `cJWK` for later use in the recovery step. Generally
speaking, the client may also store other data, such as the URL of the Tang
server or the trusted advertisement signing keys.

Expressed mathematically (capital = private key):

    s = g * S # sJWK (Server operation)
    c = g * C # cJWK
    K = s * C # dJWK

#### Recovery

To recover `dJWK` after discarding it, the client generates a third ephemeral
key (`eJWK`). Using `eJWK`, the client performs elliptic curve group addition
of `eJWK` and `cJWK`, producing `xJWK`. The client POSTs `xJWK` to the server.

The server then performs its half of the ECDH key exchange using `xJWK` and
`sJWK`, producing `yJWK`. The server returns `yJWK` to the client.

The client then performs half of an ECDH key exchange between `eJWK` and
`sJWK`, producing `zJWK`. Subtracing `zJWK` from `yJWK` produces `dJWK` again.

Expressed mathematically (capital = private key):

    e = g * E # eJWK
    x = c + e # xJWK
    y = x * S # yJWK (Server operation)
    z = s * E # zJWK
    K = y - z # dJWK

##### Understanding the Algorithm

To understand this algorithm, let us consider it without the ephemeral `eJWK`.
The math in this example depicts a standard ECDH.

    s = g * S # sJWK (Server advertisement)
    c = g * C # cJWK (Client provisioning)
    K = s * C # dJWK (Client provisioning)

    K = c * S # dJWK (Server recovery)

In the above case, the provisioning step is identical and the recovery step
does not use `eJWK`. Here, it becomes obvious that the client could simply send
its own public key (`cJWK`) to the server and receive back `dJWK`.

This example has a serious problem, however: both the identity of the client
(`cJWK`) and its secure decryption key (`dJWK`) are leaked to both the server
and any eavesdroppers. To overcome this problem, we use the ephemeral key
(`eJWK`) to blind both values.

#### Security Considerations

Let's think about the security of this system.

So long as the client discards its private key, the client cannot recover
`dJWK` without the Tang server. This is fundamentally the same assumption used
by Diffie-Hellman (and ECDH).

There are thus three avenues of attack which we will consider in turn:

1. Man-in-the-Middle
2. Compromise the client to gain access to `cJWK`
3. Compromise the server to gain access to `sJWK`'s private key

In the first case, the eavesdropper in this case sees the client send `xJWK`
and receive `yJWK`. Since, these packets are blinded by `eJWK`, only the party
that can unblind these values is the client itself (since only it has `eJWK`'s
private key). Thus, the MitM attack fails.

In the second case, it is of utmost importance that the client protect `cJWK`
from prying eyes. This may include device permissions, filesystem permissions,
security frameworks (such as SELinux) or even the use of hardware encryption
such as a TPM. How precisely this is accomplished is an exercise left to the
client implementation.

In the third case, the Tang server must protect the private key for `sJWK`.
In this implementation, access is controlled by filesystem permissions and
the service's policy. An alternative implementation might use hardware
cryptography (for example, an HSM) to protect the private key.
