#!/usr/bin/env raku

use Test;
use Gcrypt::Random;

plan 10;

does-ok my $rand = random(10, :weak), Buf[uint8], 'random weak';

is $rand.bytes, 10, 'right length';

does-ok $rand = random(10, :strong), Buf[uint8], 'random strong';

is $rand.bytes, 10, 'right length';

does-ok $rand = random(10), Buf[uint8], 'random default';

is $rand.bytes, 10, 'right length';

does-ok $rand = random(10, :very-strong), Buf[uint8], 'random very strong';

is $rand.bytes, 10, 'right length';

does-ok $rand = nonce(10), Buf[uint8], 'nonce';

is $rand.bytes, 10, 'right length';

done-testing;

