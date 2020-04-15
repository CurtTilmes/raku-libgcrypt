#!/usr/bin/env raku

use Test;
use Gcrypt::MAC;

my $text = 'The quick brown fox jumps over the lazy dog';
my $key = 'this4_#xxyh%%3hasd';

my @macs =
    HMAC_SHA256 => 'a4392b158d5af57dfe160ce616a175a0e1c22fd8cf548a4f34fa225dfc44ae3a',
    HMAC_SHA224 => '1ef145fb6d9bef5ef5096b18c1bb72370eaafe6cd933e6f98a87c1ca',
    HMAC_SHA512 => 'a9191b8e4b6ccb678af80efb7dc7a4c8724975a18cb68723ccf32e707f58d24bac5cde533205c3eea8acc3af7eb51eebc28e016fc640ad67858ec99af0eab4ad',
    HMAC_SHA384 => '7b6ab6dad5d0e5a1a3533d4f4177cb1a0926d154808efe8288a9eecceb77426ea80785349d1b961070782f07f37e4771',
    HMAC_SHA1 => '15b81d7173feafef521908aa7d1f64f3a836f31a',
    HMAC_MD5 => '28cf99d5c542403ab7af83df9ad14f18',
    HMAC_MD4 => '17f5f8b2ed157f977d8d3e35b0b1fe07',
    HMAC_RIPEMD160 => '854d5781a762e270cc2a7ad07ca72df71a06dca7',
    HMAC_TIGER => 'cf232b4bae6cc67864a02793696b680a8d1000f2baaeb27f',
    HMAC_WHIRLPOOL => '56c9612cecdec989dd48442125bbedbac14d1b53eaa35dad33edc9e566f362088bb839af969d3b6f6669e1ae79433fac05c760bdbedfd1441b166d7ca3b792da',
    HMAC_GOSTR3411_94 => 'b931e892a0f1d22fa544b704f800da238c8858267f34bc1e29063d5160f84d8e',
    HMAC_STRIBOG256 => 'b5e77f07fdff038195cc79af2abe2149b104c987b6cc2930348174957f47ba8c',
    HMAC_STRIBOG512 => 'db84e1dcdd79a4cf0f3eafba45fa82bae6372cabe4ecaf79da6487aa559641282b12017ff401f5d54e1dfbe7261e063dad9e5b5db8ea313caffbc849c08a8ff2',
    HMAC_SHA3_224 => 'c92d2ca14f408a5f696a880a5a2786f96f600ad57c4b08a1c8224db5',
    HMAC_SHA3_256 => 'e7c9ca8a5b49d0acd514887a5f6b2ea75d5e97aa70fe86bb337a53fe08be5abe',
    HMAC_SHA3_384 => 'afc7da305903c01f136a4766514309dd87015d8ea8bb48e7b20ebb34b11f2b1fb4caf355bbc12ce3efa12c5d122579fe',
    HMAC_SHA3_512 => '5580652a03e169975a3684e0d4c22dd9e684ad3db5fa730984c08599108fda82569713c193f0b9e42e301d35a954e1c3242b82e165ce4ebda88c86cf2007ee85',
    CMAC_AES => 'ea553eb59deb8333fb0cb7fdc2d6d1a1',
    CMAC_3DES => '9127487b6547c039',
    CMAC_Camellia => '9c473404e4d23faec35d9ee6f72ec704',
    CMAC_CAST5 => '0b0606da39d16125',
    CMAC_Blowfish => '4b9f0ebb20961ff6',
    CMAC_Twofish => '821ee9a809137585ec45cfd188762c6c',
    CMAC_Serpent => '3ca758cffda447ececc14c660f38bece',
    CMAC_SEED => '1f061f66e32bf8e338b33fd95d7554f9',
    CMAC_RFC2268 => '3f46993d40a5c6a7',
    CMAC_IDEA => '1d42e56675e5cd3c',
    CMAC_GOST28147 => '249a486d64fd2a59',
    GMAC_AES => 'e33eba8e6699ecbde39e89f773bf15c0',
    GMAC_Camellia => '7f08d9dc98ff4779851a7837cb93a393',
    GMAC_Twofish => '0a79001885dbc342fbd616479e237920',
    GMAC_Serpent => '62ac73460ac11cff1eff5febb6ed6aa7',
    GMAC_SEED => '87d6824998ee27419742757b3003c514',
    POLY1305 => '7b3dd3048305dc6447f73d227daabd7f',
;

plan @macs.elems;

for @macs -> (:key($algorithm), :value($hash))
{
    subtest $algorithm,
    {
        plan 4;

        isa-ok my $obj = Gcrypt::MAC.new(:$algorithm, :$key),
            'Gcrypt::MAC', "Create object for $obj.name()";

        isa-ok $obj.write($text), 'Gcrypt::MAC', "Write text $obj.name()";

        is $obj.hex(:reset), $hash, "Check hash $obj.name()";

        is $obj.write($text).hex, $hash, "Check again after reset $obj.name()";
    }
}
