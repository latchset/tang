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

##### Server Enablement
Enabling a Tang server is a simple two-step process.

First, generate two keys; one for signing and one for recovery. In this
example, we will use NIST P-521 as our group. However, you may use any group
your OpenSSL build supports.

    # tang key-gen -A secp521r1 sig
    8278b20d0ca77d56cdf5f782b15dc2df

    # tang key-gen -A secp521r1 rec
    9eefd90b72f645b4a2265d168d980765

Second, enable the service using systemd.

    # systemctl enable tang-keyd.socket
    # systemctl start tang-keyd.socket

###### Key Rotation
It is important to periodically rotate your keys. This is a simple three step
process.

First, generate new keys just like we did during setup:

    # tang key-gen -A secp521r1 sig
    fdf1338907184a940bf0822182099ddc

    # tang key-gen -A secp521r1 rec
    ff4d37b07ec821c592caef3176b57f1d

Second, disable advertisement of the previous keys:

    # tang key-mod -a 8278b20d0ca77d56cdf5f782b15dc2df
    # tang key-mod -a 9eefd90b72f645b4a2265d168d980765

Third, after some reasonable period of time you may delete the old keys.

##### Disk Management
Once you have the Tang server running, you can bind a local disk to your
Tang server.

First, you want to provision a standard LUKS encrypted disk. You should have
strong master recovery key in addition to the automatic key described in the
next steps. Failure to maintain this master recovery key could lead to data
loss.

Second, once the standard LUKS encrypted disk is previsioned, we simply
perform the binding step:

    # tang luks-bind /dev/sdc tang-server.example.com
    The server advertised the following signing keys:

      sha256:C066D185077DC08CBBEBA8190B324EA12360175BF128331EC3587F9E56E2BE0B

    Do you wish to trust these keys? [yn] y
    Enter any passphrase: <maser_recovery_key>

Third, if you have not rebuilt your initramfs since installing tang, you must
do so now:

    # dracut -f

That's it! On boot, if the device is properly setup in /etc/crypttab, systemd
will automatically unlock the disk when the Tang server is reachable.

You can list the bindings for a given LUKS disk with:

    # tang luks-list /dev/sdc
    tang-server.example.com:5700

You can also unbind a disk by simply issuing the following command:

    # tang luks-unbind /dev/sdc tang-server.example.com

