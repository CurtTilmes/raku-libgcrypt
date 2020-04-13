use NativeCall;
use Gcrypt;
use Gcrypt::Constants;

sub gcry_randomize(Blob, size_t, int32)
       is native(LIBGCRYPT) {}

multi random(Int:D $numbytes, |opts) is export
{
    samewith(buf8.allocate($numbytes), |opts)
}

multi random(Buf:D $buf,
                Bool :$weak, Bool :$strong, Bool :$very-strong) is export
{
    gcry_randomize($buf, $buf.bytes,
                   $weak ?? GCRY_WEAK_RANDOM
                         !! $very-strong ?? GCRY_VERY_STRONG_RANDOM
                                         !! GCRY_STRONG_RANDOM);
    $buf;
}

sub gcry_create_nonce(Blob, size_t)
       is native(LIBGCRYPT) {}

multi nonce(Int:D $numbytes) is export
{
    samewith buf8.allocate($numbytes)
}

multi nonce(Buf:D $buf --> Buf) is export
{
    gcry_create_nonce($buf, $buf.bytes);
    $buf
}
