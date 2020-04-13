#!/usr/bin/env raku

use Test;
use Gcrypt::Simple :ALL;

my @hashes =
    &MD5 => '9e107d9d372bb6826bd81d3542a419d6',
    &SHA1 => '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
    &RIPEMD160 => '37f332f68db77bd9d7edd4969571ad671cf9dd3b',
    &TIGER => 'f044e6721ea4126d624cb4f7e2f0b61775b0c5d2d56df085',
    &SHA256 => 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
    &SHA384 => 'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1',
    &SHA512 => '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6',
    &SHA224 => '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525',
    &MD4 => '1bee69a46ba811185c194762abaeae90',
    &CRC32 => '414fa339',
    &CRC32_RFC1510 => 'b9c60808',
    &CRC24_RFC2440 => 'a2618c',
    &WHIRLPOOL => 'b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35',
    &TIGER1 => '6d12a41e72e644f017b6f0e2f7b44c6285f06dd5d2c5b075',
    &TIGER2 => '976abff8062a2e9dcea3a1ace966ed9c19cb85558b4976d8',
    &GOSTR3411_94 => '77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294',
    &STRIBOG256 => '3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4',
    &STRIBOG512 => 'd2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe',
    &SHA3_224 => 'd15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795',
    &SHA3_256 => '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04',
    &SHA3_384 => '7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41',
    &SHA3_512 => '01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450',
    &SHAKE128 => 'f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e',
    &SHAKE256 => '2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca',
    &BLAKE2B_512 => 'a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918',
    &BLAKE2B_384 => 'b7c81b228b6bd912930e8f0b5387989691c1cee1e65aade4da3b86a3c9f678fc8018f6ed9e2906720c8d2a3aeda9c03d',
    &BLAKE2B_256 => '01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9',
    &BLAKE2B_160 => '3c523ed102ab45a37d54f5610d5a983162fde84f',
    &BLAKE2S_256 => '606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812',
    &BLAKE2S_224 => 'e4e5cb6c7cae41982b397bf7b7d2d9d1949823ae78435326e8db4912',
    &BLAKE2S_160 => '5a604fec9713c369e84b0ed68daed7d7504ef240',
    &BLAKE2S_128 => '96fd07258925748a0d2fb1c8a1167a73',
;

my $text = 'The quick brown fox jumps over the lazy dog';

plan @hashes.elems;

for @hashes -> (:key(&sub), :value($hash))
{
    try
    {
        my $obj = sub($text);
        is $obj.hex(32), $hash, "Hex Hash of $obj.name()";
    }
    skip 'Skipping', 1 if $!;
}

done-testing;
