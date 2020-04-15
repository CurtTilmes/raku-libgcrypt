use NativeCall;
use Gcrypt;
use Gcrypt::Constants;
use Gcrypt::MACHandle;

unit class Gcrypt::MAC;

has Gcrypt::MACHandle $.handle;
has Int $.algorithm;
has uint32 $.keylen;
has uint32 $.maclen;

sub gcry_mac_map_name(Str --> int32)
    is native(LIBGCRYPT) {}

sub gcry_mac_get_algo_keylen(int32 --> uint32)
    is native(LIBGCRYPT) {}

sub gcry_mac_get_algo_maclen(int32 --> uint32)
    is native(LIBGCRYPT) {}

sub gcry_mac_algo_name(int32 --> Str)
    is native(LIBGCRYPT) {}

sub gcry_mac_algo_info(int32 $algo, int32 $what, Pointer, Pointer --> int32)
    is native(LIBGCRYPT) {}

sub gcry_mac_open(Gcrypt::MACHandle $handle is rw, int32 $algo, uint32 $flags,
                  Pointer --> int32) is native(LIBGCRYPT) {}

multi submethod BUILD(Str:D :$algorithm, |opts)
{
    self.BUILD(algorithm => (gcry_mac_map_name($algorithm)
        || die X::Gcrypt::BadAlgorithm.new(:$algorithm)), |opts)
}

multi submethod BUILD(Int:D :$!algorithm,
                      :$key,
                      :$iv,
                      Bool :$secure)
{
    if gcry_mac_algo_info($!algorithm, GCRYCTL_TEST_ALGO, Pointer, Pointer)
        != 0
    {
        die X::Gcrypt::BadAlgorithm.new(algorithm => ~$!algorithm)
    }

    $!keylen = gcry_mac_get_algo_keylen($!algorithm);
    $!maclen = gcry_mac_get_algo_maclen($!algorithm);

    $!handle .= new;

    my uint32 $flags = :$secure ?? GCRY_MAC_FLAG_SECURE !! 0;

    Gcrypt.check: gcry_mac_open($!handle, $!algorithm, $flags, Pointer);

    self.setkey($_) with $key;
    self.setiv($_) with $iv;
}

method reset(--> Gcrypt::MAC)
{
    Gcrypt.check: $!handle.control(GCRYCTL_RESET, Blob, 0);
    self
}

method name(--> Str) { gcry_mac_algo_name($!algorithm) }

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

multi method setiv(Blob:D $iv)
{
    Gcrypt.check: $!handle.setiv($iv, $iv.bytes)
}

multi method setiv(Str:D $iv) { samewith $iv.encode }

method close()
{
    .close with $!handle;
    $!handle = Nil;
}

submethod DESTROY() { self.close }

multi method write(Blob:D $buf --> Gcrypt::MAC)
{
    Gcrypt.check: $!handle.write($buf, $buf.bytes);
    self
}

multi method write(Str:D $str --> Gcrypt::MAC)
{
    samewith $str.encode
}

multi method write(Any:U --> Gcrypt::MAC)
{
    self
}

method verify(Blob:D $buf --> Bool)
{
    $!handle.verify($buf, $buf.bytes) != GPG_ERR_CHECKSUM
}

method MAC(Bool :$reset --> Blob)
{
    my $buf = buf8.allocate($!maclen);
    my size_t $length = $!maclen;
    Gcrypt.check: $!handle.read($buf, $length);
    $buf.reallocate($length) if $length != $!maclen;
    self.reset() if $reset;
    $buf
}

method hex(|opts --> Str)
{
    $.MAC(|opts)».fmt("%02x").join
}
