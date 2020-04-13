use NativeCall;
use Gcrypt;
use Gcrypt::HashHandle;
use Gcrypt::Constants;

unit class Gcrypt::Hash;

has Gcrypt::HashHandle $.handle handles <reset>;
has Int $.length;

sub gcry_md_map_name(Str --> int32)
    is native(LIBGCRYPT) {}

sub gcry_md_get_algo_dlen(int32 --> int32)
    is native(LIBGCRYPT) {}

sub gcry_md_open(Gcrypt::HashHandle $handle is rw, int32 $algo, uint32 $flags
                 --> int32)
    is native(LIBGCRYPT) {}

sub gcry_md_algo_name(int32 --> Str)
    is native(LIBGCRYPT) {}

sub gcry_md_algo_info(int32 $algo, int32 $what, Pointer, Pointer --> int32)
    is native(LIBGCRYPT) {}

multi method available(Str:D $algorithm --> Bool)
{
    samewith gcry_md_map_name($algorithm)
}

multi method available(Int:D $algorithm --> Bool)
{
    gcry_md_algo_info($algorithm, GCRYCTL_TEST_ALGO, Pointer, Pointer) == 0
}

sub gcry_md_copy(Gcrypt::HashHandle $handle is rw, Gcrypt::HashHandle --> int32)
    is native(LIBGCRYPT) {}

multi submethod BUILD(Gcrypt::HashHandle:D :$!handle, Int:D :$!length) {}

multi submethod BUILD(Str:D :$algorithm, |opts)
{
    self.BUILD(algorithm => gcry_md_map_name($algorithm)
               || die X::Gcrypt::BadAlgorithm.new(:$algorithm), |opts)
}

multi submethod BUILD(Int:D :$algorithm,
                      :$key,
                      Bool :$secure,
                      Bool :$hmac,
                      Bool :$bugemu1)
{
    my uint32 $flags = ($secure  ?? GCRY_MD_FLAG_SECURE  !! 0)
                    +| ($hmac    ?? GCRY_MD_FLAG_HMAC    !! 0)
                    +| ($bugemu1 ?? GCRY_MD_FLAG_BUGEMU1 !! 0);

    $!handle .= new;

    Gcrypt.check: gcry_md_open($!handle, $algorithm, $flags);

    $!length = gcry_md_get_algo_dlen($algorithm);

    Gcrypt.check($!handle.setkey($_)) with $key;
}

method is-secure() { $!handle.is-secure() != 0 }

method clone(--> Gcrypt::Hash)
{
    my Gcrypt::HashHandle $handle .= new;
    Gcrypt.check: gcry_md_copy($handle, $!handle);
    self.bless(:$handle, :$!length)
}

method close()
{
    .close with $!handle;
    $!handle = Nil;
}

submethod DESTROY() { self.close }

method algorithm() { Gcrypt::Ciphers($!handle.algorithm) }

method name() { gcry_md_algo_name($!handle.algorithm) }

multi method write(Any:U)
{
    self;
}

multi method write(Blob:D $buf --> Gcrypt::Hash)
{
    $!handle.write($buf, $buf.bytes); self
}

multi method write(Str:D $str --> Gcrypt::Hash)
{
    samewith $str.encode
}

method digest(Int $bytes = 0 --> Blob)
{
    if $!length == 0
    {
        die X::Gcrypt::ExtendedOutput.new(algorithm => $.algorithm)
            unless $bytes > 0;

        my $buf = buf8.allocate($bytes);
        Gcrypt.check: $!handle.extract(0, $buf, $bytes);
        $buf
    }
    else
    {
        Blob.new: ($!handle.read(0) // die X::Gcrypt::Invalid.new)[^$.length]
    }
}

method hex(|opts --> Str)
{
    $.digest(|opts)».fmt("%02x").join
}

method dec(|opts --> Int)
{
    $.hex(|opts).parse-base(16)
}
