tang-nagios(1) -- A Nagios plugin for Tang
==========================================

## SYNOPSIS

`tang` -u URL

## OVERVIEW

This Nagios plugin for Tang enables Nagios to monitor a Tang server for its
basic functionality as well as performance metrics. The plugin is executed
simply by providing the base URL to the Tang service.

The plugin will test the following functionality:

1. Downloading the advertisement.
2. Verification of advertisement semantics.
3. Verification of signatures for all advertised signing keys.
4. Verification of key exchanges for all advertised exchange keys.

If any of these tests fail, an error will be generated. Upon success, the
plugin will output the following performance metrics:

* `adv`   : Time it took to fetch the advertisement (in μs).
* `exc`   : Average time of all key exchange operations (in μs).
* `nkeys` : Number of keys in the advertisement.
* `nsigk` : Number of signing keys in the advertisement.
* `nexck` : Number of exchange keys in the advertisement.

## EXAMPLES

A simple test against a localhost Tang server:

    $ ./tang -u http://localhost/
    OK|adv=21430 exc=44587 nkeys=2 nsigk=1 nexck=1

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`tang`(8)
