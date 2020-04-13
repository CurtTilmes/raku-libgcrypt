#!/usr/bin/env raku

use Test;
use Gcrypt;

lives-ok { Gcrypt.init }, 'init';

done-testing;
