#!/usr/bin/env raku

use Test;
use Gcrypt;

plan 3;

ok my $version = Gcrypt.version(), 'Get Version';
diag "libgcrypt version $version";

ok Gcrypt.config(), 'Config';

ok Gcrypt.config('ciphers'), 'Config ciphers';

done-testing;
