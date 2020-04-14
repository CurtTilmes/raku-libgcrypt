# Raku Gcrypt - Bindings for GNU Libgcrypt

[![Build Status](https://travis-ci.org/CurtTilmes/raku-libgcrypt.svg)](https://travis-ci.org/CurtTilmes/raku-libgcrypt)

* [Introduction](#introduction)
* [Message Digest (Hash)](#message-digest-hash)
* [Symmetric cryptography ciphers](#symmetric-cryptography-ciphers)
* [Random](#random)
* [Passphrase](#passphrase)
* [libgcrypt versions/features](#libgcrypt-versionsfeatures)
* [Multi-threading](#multi-threading)
* [Installation](#installation)
* [License](#license)

## Introduction

A [Raku](https://raku.org/) interface to
[libgcrypt](https://gnupg.org/software/libgcrypt/).

    Libgcrypt is a general purpose cryptographic library originally
    based on code from GnuPG. It provides functions for all
    cryptograhic building blocks: symmetric cipher algorithms (AES,
    Arcfour, Blowfish, Camellia, CAST5, ChaCha20 DES, GOST28147,
    Salsa20, SEED, Serpent, Twofish) and modes
    (ECB,CFB,CBC,OFB,CTR,CCM,GCM,OCB,POLY1305,AESWRAP), hash
    algorithms (MD2, MD4, MD5, GOST R 34.11, RIPE-MD160, SHA-1,
    SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA3-224, SHA3-256,
    SHA3-384, SHA3-512, SHAKE-128, SHAKE-256, TIGER-192, Whirlpool),
    MACs (HMAC for all hash algorithms, CMAC for all cipher
    algorithms, GMAC-AES, GMAC-CAMELLIA, GMAC-TWOFISH, GMAC-SERPENT,
    GMAC-SEED, Poly1305, Poly1305-AES, Poly1305-CAMELLIA,
    Poly1305-TWOFISH, Poly1305-SERPENT, Poly1305-SEED), and
    random numbers.

**Note, this is still a work in progress, more features may or may not
  be forthcoming!!  Patches welcome!!**

# Usage

## Message Digest (Hash)

A [message digest or cryptographic hash
function](https://en.wikipedia.org/wiki/Cryptographic_hash_function)
is a function that maps data of arbitrary size to a bit string of
fixed size, the hash or digest.

```
use Gcrypt::Simple :MD5;       # Import routines you specify, or use :ALL for all

say MD5('Some text').hex;      # 9db5682a4d778ca2cb79580bdb67083f

say MD5(slurp).hex;            # print md5sum of STDIN

my $obj = MD5;                 # Get a new object
$obj.write("$_\n") for lines;  # Incremental calculation
say $obj.digest;               # Blob
say $obj.hex;                  # Hex string
say $obj.dec;                  # Decimal
$obj.reset;                    # Reuse object on another message
```

Available Hashes:

MD5 SHA1 RIPEMD160 TIGER SHA256 SHA384 SHA512 SHA224 MD4 CRC32
CRC32_RFC1510 CRC24_RFC2440 WHIRLPOOL TIGER1 TIGER2 GOSTR3411_94
STRIBOG256 STRIBOG512 SHA3_224 SHA3_256 SHA3_384 SHA3_512 SHAKE128
SHAKE256 BLAKE2B_512 BLAKE2B_384 BLAKE2B_256 BLAKE2B_160 BLAKE2S_256
BLAKE2S_224 BLAKE2S_160 BLAKE2S_128

See [Available hash algorithms](https://gnupg.org/documentation/manuals/gcrypt/Available-hash-algorithms.html) for more details on each algorithm.

Note that SHAKE128 and SHAKE256 are extendable-output functions (XOF),
and can produce variable amounts of output.  Pass in the number of
bytes you want to `digest`, `hex` or `dec`:
```
use Gcrypt::Simple :SHAKE128;
say SHAKE128('Some text').hex(16);
```

## Message Authentication Codes (MAC)

A [message authentication
code](https://en.wikipedia.org/wiki/Message_authentication_code) is a
short code used to authenticate that a message came from the stated
sender (its authenticity) and has not been changed.

To create one, you need a key and the message.

```
use Gcrypt::Simple :HMAC_MD5;       # Select algorithm, or :ALL for all

say HMAC_MD5('mykey', 'my message').hex;
# f50357b6299b741cf6b1c63073e54112

my $obj = HMAC_MD5('mykey');        # Create object
$obj.write('my message');           # Add data
say $obj.MAC;                       # Blob
say $obj.hex;                       # Hex string
$obj.reset;                         # Reuse object on another message
```

Key is truncated or 0 extended to the size for the algorithm.
(`$obj.keylen` will tell you the algorithm's key size).

Available MAC algorithms:

HMAC_SHA256 HMAC_SHA224 HMAC_SHA512 HMAC_SHA384 HMAC_SHA1 HMAC_MD5
HMAC_MD4 HMAC_RIPEMD160 HMAC_TIGER HMAC_WHIRLPOOL HMAC_GOSTR3411_94
HMAC_STRIBOG256 HMAC_STRIBOG512 HMAC_SHA3_224 HMAC_SHA3_256
HMAC_SHA3_384 HMAC_SHA3_512 CMAC_AES CMAC_3DES CMAC_Camellia
CMAC_CAST5 CMAC_Blowfish CMAC_Twofish CMAC_Serpent CMAC_SEED
CMAC_RFC2268 CMAC_IDEA CMAC_GOST28147 GMAC_AES GMAC_Camellia
GMAC_Twofish GMAC_Serpent GMAC_SEED POLY1305

See [Available MAC algorithms](https://gnupg.org/documentation/manuals/gcrypt/Available-MAC-algorithms.html) for more details on each algorithm.

## Symmetric cryptography ciphers
```
use Gcrypt::Simple :IDEA;

my $key = 'foobar';
my $encrypted = IDEA($key).encrypt('Some text');
say IDEA($key).decrypt($encrypted);

my $obj = IDEA($key);                       # Create object
my $encrypted = $obj.encrypt('Some text');
$obj.reset;                                 # Reuse object
say $obj.decrypt($encrypted);
```

Available Ciphers:

IDEA DES3 CAST5 Blowfish AES AES192 AES256
Twofish RC4 DES Twofish128 Serpent128 Serpent192
RFC2268_40 SEED Camellia128 Camellia192 Camellia256
Salsa20 Salsa20R12 GOST28147 ChaCha20

See [Available ciphers](https://gnupg.org/documentation/manuals/gcrypt/Available-ciphers.html) for more details on each algorithm.

## Random
```
use Gcrypt::Random;

my $rand = random(10);
# Buf[uint8].new(148,229,159,236,230,13,154,226,245,23)
my $rand = random(10, :weak);           # actually the same as strong
my $rand = random(10, :strong);         # default
my $rand = random(10, :very-strong);    # stronger
my $rand = nonce(10);                   # Actually weak, but unpredictable
```

Returns a buffer of random bytes.

See [Quality of random numbers](https://gnupg.org/documentation/manuals/gcrypt/Quality-of-random-numbers.html) for more information.

## Passphrase

Derive a key from a string

```
use Gcrypt::Passphrase;

my $passphrase = "This is a long and complicated passphrase.";

my $key = key-from-passphrase($passphrase,
                              keysize => 16,
                              algorithm => 'SIMPLE_S2K',
                              subalgorithm => 'SHA1');

$key = key-from-passphrase($passphrase,
                           keysize => 64,
                           algorithm => 'ITERSALTED_S2K',
                           subalgorithm => 'SHA512',
                           iterations => 12,
                           salt => 'abcdefgh');

```
See [Key Derivation](https://gnupg.org/documentation/manuals/gcrypt/Key-Derivation.html) for more information.

# libgcrypt versions/features

You can check the version by calling `Gcrypt.version` which returns
the version as a string:

```
use Gcrypt;
say Gcrypt.version;   # '1.7.6beta' or '1.8.1' or whatever
```

You can query the library for its capabilities with `Gcrypt.config`:

```
use Gcrypt;
say Gcrypt.config;               # Get all configuration
say Gcrypt.config('ciphers');    # List available ciphers
say Gcrypt.config('digests');    # List available digests

# Multi-threading

Most Gcrypt actions are thread-safe.

The error strings use a static memory buffer, so make sure only one
thread is printing out an `Exception` message at a time.  You can use
the exception's integer `code` safely.

## Installation

Many distributions already have libgcrypt installed, but if not, get it
first:
* For debian or ubuntu: `apt install libgcrypt20`
* For alpine: `apk add libgcrypt`

Then `zef install Gcrypt`.

## License

This work is subject to the Artistic License 2.0.

See [LICENSE](LICENSE) for more information.
