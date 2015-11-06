# Tang

#### Welcome to Tang!
Tang is a system service and client for binding data to your local network.
The concept of this application is simple, but let's look at an example.

*NOTE*: Tang is a work in progress and is currently unstable. Do *NOT* use it.

##### Use Case: Network-bound Automatic Disk Decryption
Suppose you have a disk with sensitive data. If it breaks, you can't just
send it back for repair. This could expose the data. Nor can you just throw
it away.

You could encrypt the disk. This would let you repair or discard the disk. But
now you have to remember a password and manually enter it on every boot. This
doesn't scale.

What you need is a way to encrypt the disk using a high entropy key and then
making it so that this key can be used automatically when you are on the
network, but not otherwise.

The solution to this problem is encrypting the key in such a way that it can
only be decrypted when you are on the network. Hence, you bind the key to
the network.

This is precisely what Tang does.

##### Installation

    $ ./configure
    $ make
    $ sudo make install

##### Enablement
Enabling a Tang server is a simple two-step process.

First, generate two keys; one for signing and one for recovery. In this
example, we will use NIST P-521 as our group. However, you may use any group
your OpenSSL build supports.

    $ tang-gen -A secp521r1 sig
    8278b20d0ca77d56cdf5f782b15dc2df

    $ tang-gen -A secp521r1 rec
    9eefd90b72f645b4a2265d168d980765

Second, enable the service using systemd.

    $ systemctl enable tang.socket
    $ systemctl start tang.socket

##### Key Rotation
It is important to periodically rotate your keys. This is a simple three step
process.

First, generate new keys just like we did during setup:

    $ tang-gen -A secp521r1 sig
    fdf1338907184a940bf0822182099ddc

    $ tang-gen -A secp521r1 rec
    ff4d37b07ec821c592caef3176b57f1d

Second, disable advertisement of the previous keys:

    $ tang-mod -a 8278b20d0ca77d56cdf5f782b15dc2df
    $ tang-mod -a 9eefd90b72f645b4a2265d168d980765

Third, after some reasonable period of time you may delete the old keys.
