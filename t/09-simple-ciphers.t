#!/usr/bin/env raku

use Test;
use Gcrypt;
use Gcrypt::Simple :ALL;

Gcrypt.init(version => '1.7.6');

my $plaintext = 'The quick brown fox jumps over the lazy dog';
my $key = 'this4_#xxyh%%3hasd';

my @ciphers = &IDEA, &DES3, &CAST5, &Blowfish, &AES, &AES192, &AES256,
&Twofish, &RC4, &DES, &Twofish128, &Serpent128, &Serpent192,
&RFC2268_40, &SEED, &Camellia128, &Camellia192, &Camellia256,
&Salsa20, &Salsa20R12, &GOST28147, &ChaCha20;

plan 3 * @ciphers.elems;

for @ciphers -> $cipher
{
    isa-ok my $obj = $cipher($key), 'Gcrypt::Cipher',
        "Create $obj.name()";

    isa-ok my $encrypted = $obj.encrypt($plaintext), 'Buf[uint8]',
        "Encrypt $obj.name()";

    is $obj.reset.decrypt($encrypted), $plaintext,
        "Decrypt $obj.name()";
}

done-testing;
