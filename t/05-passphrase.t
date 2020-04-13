#!/usr/bin/env raku

use Test;
use Gcrypt::Passphrase;

my $passphrase = "This is a long and complicated passphrase.";

plan 2;

cmp-ok key-from-passphrase($passphrase,
                           keysize => 16,
                           algorithm => 'SIMPLE_S2K',
                           subalgorithm => 'SHA1'),
    'eqv',
    buf8.new(184,126,47,63,212,246,76,34,65,144,38,106,166,65,243,49),
    'Key via SIMPLE_S2K and SHA1';

cmp-ok key-from-passphrase($passphrase,
                           keysize => 64,
                           algorithm => 'ITERSALTED_S2K',
                           subalgorithm => 'SHA512',
                           iterations => 12,
                           salt => 'abcdefgh'),
    'eqv',
    buf8.new(213,220,87,124,73,27,28,173,46,131,167,77,90,87,19,240,125,158,223,174,162,164,230,251,215,209,8,206,80,57,99,86,13,169,21,238,141,177,185,198,217,11,193,235,160,73,136,9,161,250,235,168,154,1,30,98,212,87,113,90,151,243,5,131),
    'Key via ITERSALTED_S2K and SHA512';

done-testing;
