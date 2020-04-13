#!/usr/bin/env raku

use Test;
use Gcrypt;

lives-ok { Gcrypt.init(version => '1.7.6') }, 'init';

done-testing;
