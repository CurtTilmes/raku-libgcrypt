#!/usr/bin/env raku

use Test;
use Gcrypt::Constants;
use Gcrypt::Cipher;

my $plaintext = 'The quick brown fox jumps over the lazy dog';
my $key = 'this4_#xxyh%%3hasd';

plan Gcrypt::Ciphers.enums.elems;

for Gcrypt::Ciphers.enums.kv -> $name, $algorithm
{
    subtest $name,
    {
        plan 5;

        if Gcrypt::Cipher.available($algorithm)
        {
            isa-ok my $obj = Gcrypt::Cipher.new(:$algorithm, :$key),
                Gcrypt::Cipher, 'open';

            ok my $encrypted = $obj.encrypt($plaintext), 'encrypt';

            ok $obj.reset, 'reset';

            ok my $decrypted = $obj.decrypt($encrypted), 'decrypt';

            is $decrypted, $plaintext, 'correct';
        }
        else
        {
            skip "Unknown algorithm $algorithm", 5;
        }
    }
}

done-testing;
