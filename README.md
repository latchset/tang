# Tang

#### Welcome to Tang!
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
every key ever used, Tang never sees a single client key. Further, Tang even
supports a fully anonymous mode where the server never even gains any
identifying information from the client.

|                |   Escrow   |   Tang   |
|---------------:|:----------:|:--------:|
|      Stateless |     No     |    Yes   |
|          X.509 |  Required  | Optional |
|        SSL/TLS |  Required  | Optional |
| Authentication |  Required  | Optional |
|      Anonymous | Impossible | Possible |

#### Getting Started
##### Dependencies

Tang requires a few other software libraries:

1. http-parser - https://github.com/nodejs/http-parser
2. systemd - https://github.com/systemd/systemd
3. jose - https://github.com/latchset/jose

##### Building and Installing from Source

Building Tang is fairly straightforward:

    $ autoreconf -if
    $ ./configure --prefix=/usr
    $ make
    $ sudo make install

You can even run the tests if you'd like:

    $ make check

##### Server Enablement

Enabling a Tang server is a simple two-step process.

First, we need to generate a signing key and at least one encryption or exchange key.

    # jose gen -t '{"alg": "ES256"}' \
      > /var/db/tang/keys/sig.jwk

    # jose gen -t '{"alg": "ECDH-ES"}' \
      > /var/db/tang/keys/enc.jwk

    # jose gen -t '{"kty": "EC", "crv": "P-256", "key_ops": ["deriveKey"]}' \
      > /var/db/tang/keys/exc.jwk

Second, enable the service using systemd socket activation.

    # systemctl enable tangd.socket
    # systemctl start tangd.socket

That's it! You're up and running!

##### Key Rotation
It is important to periodically rotate your keys. This is a simple three step
process. In this example, we will rotate only a signing key; but all key types
should be rotated.

First, generate a new key:

    # jose gen -t '{"alg": "ES256"}' \
      > /var/db/tang/keys/newsig.jwk

Second, disable advertisement of the previous key:

    # mv /var/db/tang/keys/sig.jwk /var/db/tang/keys/.sig.jwk

Third, after some reasonable period of time you may delete the old keys. You
should only delete the old keys when you are sure that no client require them
anymore. You have been warned.

#### Tang Protocol

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
|   `POST` | `/rec/{kid}` | Recover key using specified recovery key      |
|    `GET` | `/blk`       | List blacklisted BIDs                         |
|    `PUT` | `/blk/{bid}` | Add a BID to the blacklist                    |
| `DELETE` | `/blk/{bid}` | Remove a BID from the blacklist               |

##### Advertisement

The advertisement reply message contains a JWS-signed JWKSet.

The (outer) JWS contains signatures using all of the advertised signing JWKs.

The (inner) JWKSet contains all of the advertised public JWKs. This includes
all advertised signing, encryption and exchange JWKs.

Typically, a client will perform "Trust On First Use" in order to trust the
server's advertisement. However, once the client trusts at least one signing
JWK, further advertisements can be requested using that signing JWK. This
allows clients to upgrade their chain of trust.

##### Wrapping Mode

Wrapping mode provides an experience similar to escrows using standard
off-the-shelf encryption. It is accomplished by simply nesting JWE objects.

In wrapping mode, the POST request and reply bodies are JWE objects.

###### Provisioning

The client selects one of the server's encryption JWKs (henceforth: `wJWK`;
identified by the use of `wrapKey` in the `wJWK`'s `key_ops` attribute) and
generates:

1. a unique, collision resistant, base64url-encoded binding identifier (`BID`)
2. a protection JWK (`pJWK`)
3. a data JWK (`dJWK`)

After data has been encrypted using the `dJWK`, the `dJWK` is itself encrypted
using the `pJWK`, producing an inner JWE. This inner JWE is encrypted again
using the `wJWK`, producing a middle JWE. The `BID` is specified in the
`tang.bid` attribute of the JWE protected header of the middle JWE. Finally,
the `dJWK` is discarded. The stored metadata consists of:

1. the `wJWK`
2. the `pJWK`
3. the middle JWE

The middle JWE might conceptually look like this:

    JWE(wJWK, {"prot": {"tang.bid": BID}},
        JWE(pJWK, {}, dJWK))

###### Recovery

When the client wishes to recover the `dJWK`, a new ephemeral JWK (`eJWK`) is
generated and stored in the `tang.jwk` attribute of the JWE shared header
in the middle JWE. The middle JWE is then encrypted - again, using the `wJWK` -
producing an outer JWE. It is this outer JWE that is POSTed to the server
(using the KID of `wJWK` in the path of the request).

The outer JWE might conceptually look like this:

    JWE(wJWK, {},
        JWE(wJWK, {"prot": {"tang.bid": BID}, "unprot": {"tang.jwk": eJWK}},
            JWE(pJWK, {}, dJWK)))

The server decrypts the outer and middle JWEs and verifies the `BID` against a
blacklist to determine if the binding has been revoked. Then, the server
re-encrypts the inner JWE using the `eJWK`, creating an ephemeral JWE, and
returns it to the client.

The client then decrypts the ephemeral JWE using the `eJWK`, producing the
inner JWE. Finally, the client decrypts the inner JWE using the `pJWK`,
producing the recovered `dJWK`.

###### Security Considerations
Let's think about the security of this system. We presume that the client's
proper mode of operation is that it has the unrevoked, stored binding metadata
in the presence of Tang server. Further, we presume the underlying cryptosystem
is secure. Therefore, our attack model is that the attacker has either the
stored metadata or Tang server access (possibly compromised), but not both.

In the first case, since the attacker does not have the private key required
to decrypt the middle JWE the attack fails. In the second case, the attacker
doesn't have any access to the encrypted `eJWK` unless the Tang server is
compromised. But even in this case, a compromised Tang server sees only the
inner JWE. While this can be used to uniquely identify the client, the `eJWK`
cannot be recovered without the `pJWK` (which the attacker doesn't have).

Since the use of the blacklist artificially restricts presence, an attacker
might have possession of a revoked metadata and network access to the Tang
server. In this case, the attacker wants to bypass the blacklist. A
compromised server cannot protect against this attack. However, if the server
is uncompromised, the only possible attack is to modify the `BID` after the
middle JWE is created. Since the `BID` is stored exclusively in the JWE
protected header -- which by definition prevents modification -- the attack
fails.

##### Anonymous Mode

Tang provides a secondary mode of operation called anonymous mode which is an
implementation of the McCallum-Relyea exchange.

Anonymous mode is anonymous (duh!). The Tang server never sees any information
that can be used to identify the client. The downside to this anonymity is
that since the binding cannot be identified, it cannot be revoked. Therefore,
there is no binding identifier and no blacklist check.

Anonymous mode is fast. Since it is essentially a key exchange, it is far less
CPU intensive than Wrapping Mode.

The basic idea of anonymous mode is that the client performs an ECDH key
exchange in order to produce the binding key, but then discards its own private
key so that the Tang server is the only party that can reconstitute the
binding key. Additionally, a third, ephemeral key is used to blind the client's
public key and the binding key so that only the client can unblind them.

In wrapping mode, the POST request and reply bodies are JWK objects.

###### Provisioning

The client selects one of the Tang server's exchange keys (`sJWK`; identified
by the use of `deriveKey` in the `sJWK`'s `key_ops` attribute). The client
generates a new (random) JWK (`cJWK`). The client performs its half of a
standard ECDH exchange producing `dJWK` which it uses to encrypt the data.
Afterwards, it discards `dJWK` and the private key from `cJWK`.

The stored metadata is:

1. the `sJWK` (public key)
2. the `cJWK` (public key)

Expressed mathimatically (capital = private key):

    s = g * S # sJWK (Server operation)
    c = g * C # cJWK
    K = s * C # dJWK

###### Recovery

To recover the session key, the client generates a third ephemeral key
(`eJWK`). Using `eJWK`, the client performs elliptic curve group addition of
`eJWK` and `cJWK`, producing `xJWK`. The client POSTs `xJWK` to the server
(using the `kid` of `sJWK` in the path of the request).

The server then performs its half of the ECDH key exchange using `xJWK` and
`sJWK`, producing `yJWK`. The server returns `yJWK` to the client.

The client then performs half of an ECDH key exchange between `eJWK` and
`sJWK`, producing `zJWK`. Subtracing `zJWK` from `yJWK` produces `dJWK` again.

Expressed mathimatically (capital = private key):

    e = g * E # eJWK
    x = c + e # xJWK
    y = x * S # yJWK (Server operation)
    z = s * E # zJWK
    K = y - z # dJWK

###### Security Considerations

To understand this algorithm, let us consider it without the ephemeral `eJWK`:

    s = g * S # sJWK (Server operation)
    c = g * C # cJWK
    K = s * C # dJWK

    K = c * S # dJWK (Server operation)

In the above case, the provisioning step is identical and the recovery step
does not use `eJWK`. Here, it becomes obvious that the client could simply send
its own public key (`cJWK`) to the server and receive back `dJWK`.

This example has a serious problem, however: both the identity of the client
(`cJWK`) and its secure decryption key (`dJWK`) are leaked to both the server
and any eavesdroppers. To overcome this problem, we use the ephemeral key
(`eJWK`) to blind both values.

Thus, we have a similar threat model as in wrapping mode.

First, since the client discarded the private key of `cJWK`, the attacker
cannot recover `dJWK` without the Tang server.

Second, an attacker cannot observe any identifying information or recover
`dJWK`; even if the Tang server is compromised.

##### Blacklist Management

Although the blacklist management plugin is installed by default, it is not
enabled. The reason for this is that remote blacklist management absolutely
does require authentication (you don't want attackers freely able to manage
the blacklist!). However, the Tang server does not provide support for this
authentication.

Thus, if you wish to enable blacklist management, simply put the Tang server
behind Apache or some other web server and properly authenticate access to
these APIs. Then, edit the systemd service unit file to instantiate the
blacklist management plugin during startup.
