#!/usr/bin/env raku

use Test;
use Gcrypt;

plan 1;

ok my $version = Gcrypt.version(), 'Get Version';
diag "libgcrypt version $version";

done-testing;
