`dheluks` Specification
=======================

Overview
--------

The `dheluks` protocol is designed to secure the transfer of a [LUKS](https://gitlab.com/cryptsetup/cryptsetup/blob/master/README.md) disk encryption password between a system administrator and a remote server. 

Motivation
----------

Server colocation facilities use serial cables to transfer passwords from serial console to server, despite the fact that they are [easily sniffable](http://www.keydemon.com/rs232_logger/). `dheluks` uses the [elliptic curve Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman) (ECDH) to create a cryptographically secure channel over the serial cable, which mitigates the threat of transferring a password in the clear.

Threat Model
------------

`dheluks` is designed to protect against a passive adversary who is monitoring traffic at the serial console or along the serial cable. Security against an active adversary who can intercept and reroute traffic, or against a passive adversary who has access to the internal state of the server, is left to future work.

Server-side Deployment
----------------------

In this section we discuss how to deploy `dheluks` on a server running [Debian](https://www.debian.org) (or a Debian derivative).

The `dheluks` server-side protocol extends the file `/lib/cryptsetup/askpass`, which is part of the [cryptsetup package](https://packages.qa.debian.org/c/cryptsetup.html). To deploy `dheluks` on your server, execute the following steps:

1. Clone the repository and move it into your desired build directory.
2. Install the necessary build dependencies:

        apt install build-essential nettle-dev
3. Make the `dheluks` version of askpass:

        make askpass
4. Replace the askpass file in your server’s `/lib/cryptsetup` directory with the new askpass (you may want to keep a copy of the old `askpass`).

        cp /lib/cryptsetup/askpass{,.no-dheluks}
        mv yourbuildpath/askpass /lib/cryptsetup/askpass
5. Rebuild the initramfs for all kernels (you may want to keep a copy of the old initramfs, which lives in `/boot`):

        cp /boot/initrd.img-$(uname -r){,.no-dheluks}
        update-initramfs -u -k all   
6. Reboot the server.

Client-side Deployment
----------------------

In this section we discuss how to build and use the `dheluks` client, which must interoperate with a `dheluks`-enabled  server.  For administrators running non-`Debian` derivatives, see `Writing a Client` below.

A basic `dheluks` client is included in the `dheluks` git repository.  To deploy the sample client, execute the following steps:
   
1. Complete steps 1-2 from the server-side deployment.
2. Make the `dheluks` client:

        make client
3. Run the client when you receive a prompt from a `dheluks`-enabled server:

        ./client
and follow the instructions (see `Example Run` below).


Writing a Client
----------------

A functional `dheluks` client must adhere to the `dheluks` string specification as well as several cryptographic specifications. The `dheluks` string consists of the `dheluks` header (currently `dheluks:0`) followed by a `base64`-encoded blob that represents either a `dheluks prompt`, which is issued by the server, or a `dheluks response`, which is issued by the client.

1. A decoded `dheluks prompt` MUST contain (in order):
* a 32-byte public key

2. A decoded `dheluks response` MUST contain (in order):
* a 32-byte public key
* a 12-byte nonce
* a 16-byte ciphertext message authentication code (ciphertext digest)
* a dynamically-sized ciphertext containing the encrypted password

3. A decrypted ciphertext MUST contain (in order):
* a 4-byte header with the number of bytes in the password, represented in network-layer format (use `htonl` and `ntohl` for host-to-network and network-to-host layers, respectively) 
* the password
* arbitrary padding such that the ciphertext is a multiple of 64 bytes (the ciphertext block size)

4. Cryptographic specifications:
* all operations are performed over [Curve25519](https://en.wikipedia.org/wiki/Curve25519) with base point X = 9
* private keys are 32-byte scalars
* public keys are 32-byte points on the curve, generated according to [ECDH](https://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman)
* encryption and decryption use [ChaCha-Poly1305](https://en.wikipedia.org/wiki/Poly1305)
* nonces are 12-byte scalars
* message authentication codes are 16-byte scalars, generated from the ciphertext digest
* ciphertext size must be a multiple of 64 bytes

These functions and parameters are defined in depth in the `dheluks` library and the [`nettle` library](http://www.lysator.liu.se/~nisse/nettle/nettle.html), which we strongly recommend for building an easily interoperable client.

Example Run
-----------

`dheluks prompt` (server):

	dheluks0:DX+KluJB2yCDk4z1bjqO/vqcd5P457SLsq638mUHo0k=
    Please unlock disk vda5_crypt: 

`dheluks response` (client):

    Please enter the server's dheluks string: dheluks0:XhZfnSMXfVI/YNS1HkMzhvZfVWIh5xSmTB3oCQ6jhHY= 

    Please enter your password: (no echo)

	dheluks0:akVgp3HgbPMXbsRLmQnU/LHGCYlY6HWXkvRCvWXRER0Wb6riTzdQNg9VjFmjlAErth2l3JliLiVjU0ZiXGAmwbvPnOhy07FJy+QcNHDbBYheC1NW1IMpTe0jGuHj4k0X4c75NHzpCbwP8BHKp1IH9ngN2un9UMN8Wx/FAw==

    Paste the above string (including header) into the dheluks-enabled server prompt.

On Success:

    cryptsetup (vda5_crypt): set up successfully
