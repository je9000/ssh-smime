ssh-smime
=========

S/MIME encryption with SSH RSA public keys.

Used to securely share files with someone when all you have is their SSH public
key.


Synopsis
=======

SSH Public key extraction:

grep ssh-rsa ~recipient1/.ssh/authorized_keys | head -1 > recipient1-key

Encryption:

ssh-smime -i input-file -o encrypted-file recipient1-key recipient2-key

Decryption:

openssl smime -decrypt -in encrypted -inkey ~/.ssh/id_rsa -out decrypted


Description
===========

ssh-smime performs S/MIME file encryption using SSH RSA public keys. This
allows files to be encrypted for one or more recipients when all you possess is
that recipient's RSA public key. This means, for example, you can encrypt a
file for a user given only the keys listed in that user's SSH authorized_keys
file. Recipients can then decrypt the file with OpenSSL.

The authorized_keys file can contain multiple keys, one per line, so before
using with this tool a single RSA2 key must be extracted into a separate file.

Since this software encrypts using S/MIME, multiple recipients are supported.
Each recipient will be able to decrypt all of the encrypted data with their
key. This feature is useful for sharing data with multiple users.

This software was primarily designed for the use case of sharing encrypted data
when exchanging more than SSH keys is impractical. When possible, a full
OpenPGP (such as GPG or NetPGP) implementation should be used with dedicated
keys.


Security Considerations
=======================

The author recommends an OpenPGP implementation (such as GPG or NetPGP) be used
instead of this software whenever possible.

More specifically, it is generally not advisable to use the same RSA keys for
both signing and encryption. SSH2 uses RSA keys for signing, and this software
uses them for encryption, so a best practice would be to not use this software
at all and to use an OpenPGP implementation instead. However, since SSH only
ever signs requests using PKCS1, most concerns regarding subverting the signing
mechanism do not apply here (as long as the RSA keys are never used for blind
signing). Using a large symmetric key also helps mitigate this risk.

Regardless, it is still not advisable to rely on this tool for all your data
encryption needs. However there are times where exchanging another key is
impractical and in those situations this software may be the best option.


Limitations
===========

Only SSH2 (public) keys are supported.

The symmetric encryption cipher used is fixed to AES-256-CBC.

Files are always read as binary, which doesn't strictly meet the S/MIME
standard but I believe is more useful.

See also: Security Considerations.


License
=======

This software is licensed under the same terms as OpenSSL itself. See the
LICENSE file for details.


Author
======

John Eaglesham

