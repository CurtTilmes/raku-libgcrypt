use NativeCall;
use Gcrypt;
use Gcrypt::CipherHandle;
use Gcrypt::Constants;

unit class Gcrypt::Cipher;

has Gcrypt::CipherHandle $.handle;
has Int $.algorithm;
has size_t $.keylen;
has size_t $.blklen;
has Bool $.bin;
has Gcrypt::Padding $.padding;

sub gcry_cipher_algo_info(int32 $algo, int32 $what, Blob, size_t --> int32)
    is native(LIBGCRYPT) {}

sub gcry_cipher_open(Gcrypt::CipherHandle $handle is rw, int32 $algo,
                     int32 $mode, uint32 $flags --> int32)
    is native(LIBGCRYPT) {}

sub gcry_cipher_map_name(Str --> int32)
    is native(LIBGCRYPT) {}

sub gcry_cipher_algo_name(int32 --> Str)
    is native(LIBGCRYPT) {}

sub gcry_cipher_get_algo_keylen(int32 --> size_t)
    is native(LIBGCRYPT) {}

sub gcry_cipher_get_algo_blklen(int32 --> size_t)
    is native(LIBGCRYPT) {}

method available(Str:D $algorithm)
{
    Gcrypt.init;
    my $algo = gcry_cipher_map_name($algorithm) || return False;
    gcry_cipher_algo_info($algo, GCRYCTL_TEST_ALGO, Blob, 0) == 0;
}

multi submethod BUILD(Str:D :$algorithm, |opts)
{
    self.BUILD(algorithm => (gcry_cipher_map_name($algorithm)
               || die X::Gcrypt::BadAlgorithm.new(:$algorithm)), |opts)
}

multi submethod BUILD(Int:D :$!algorithm,
                :$mode is copy,
                :$key,
                :$iv,
                :$!padding = GCRYPT_PADDING_STANDARD,
                Bool :$!bin,
                Bool :$secure,
                Bool :$enable-sync,
                Bool :$CBC-CTS,
                Bool :$CBC_MAC)
{
    Gcrypt.init;

    $!keylen = gcry_cipher_get_algo_keylen($!algorithm);
    $!blklen = gcry_cipher_get_algo_blklen($!algorithm);

    if $mode ~~ Str
    {
        $mode = Gcrypt::CipherModes::{"GCRY_CIPHER_MODE_$mode.uc()"}
        // die X::Gcrypt::BadMode.new(:$mode)
    }
    else
    {
        $mode //= $!blklen > 1 ?? GCRY_CIPHER_MODE_CBC
            !! GCRY_CIPHER_MODE_STREAM;
    }

    $!handle .= new;

    Gcrypt.check: gcry_cipher_open($!handle, $!algorithm, $mode, 0);

    self.setkey($_) with $key;
    self.setiv($_) with $iv;
}

multi method setkey(Blob:D $key where *.bytes == $!keylen)
{
    Gcrypt.check: $!handle.setkey($key, $key.bytes)
}

multi method setkey(Blob:D $key where *.bytes < $!keylen)
{
    samewith Buf.new($key).append(0 xx $!keylen - $key.bytes)
}

multi method setkey(Blob:D $key where *.bytes > $!keylen)
{
    samewith Buf.new($key).reallocate($!keylen)
}

multi method setkey(Str:D $key) { samewith $key.encode }

multi method setiv(Blob:D $iv where *.bytes == $!blklen)
{
    Gcrypt.check: $!handle.setiv($iv, $iv.bytes)
}

multi method setiv(Blob:D $iv where *.bytes < $!blklen)
{
    samewith Buf.new($iv).append(0 xx $!blklen - $iv.bytes)
}

multi method setiv(Blob:D $iv where *.bytes > $!blklen)
{
    samewith Buf.new($iv).reallocate($!blklen)
}

multi method setiv(Str:D $iv) { samewith $iv.encode }

multi method setiv()
{
    samewith Buf.new(0 xx $!blklen)
}

method close()
{
    .close with $!handle;
    $!handle = Nil;
}

submethod DESTROY() { self.close }

multi method encrypt(Blob:D $in where *.bytes %% $!blklen)
{
    my $out = buf8.allocate($in.bytes);
    Gcrypt.check: $!handle.encrypt($out, $out.bytes, $in, $in.bytes);
    $out
}

multi method encrypt(Blob:D $in where !(*.bytes %% $!blklen))
{
    samewith Buf.new($in).append(0 xx $!blklen - $in.bytes % $!blklen)
}

multi method encrypt(Str:D $in, |opts)
{
    samewith $in.encode, |opts
}

multi method decrypt(Blob:D $in, Bool :$bin = $!bin)
{
    my $out = buf8.allocate($in.bytes);
    Gcrypt.check: $!handle.decrypt($out, $out.bytes, $in, $in.bytes);
    return $out if $bin;
    my $bytes = $out.bytes;
    $bytes-- while $out[$bytes-1] == 0;
    $out.reallocate($bytes).decode
}

method name(--> Str)
{
    gcry_cipher_algo_name($!algorithm)
}

method reset()
{
    Gcrypt.check: $!handle.control(GCRYCTL_RESET, Pointer, 0);
    self
}
