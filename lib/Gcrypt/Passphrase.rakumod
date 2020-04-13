use NativeCall;
use Gcrypt;
use Gcrypt::Constants;

sub gcry_kdf_derive(Blob $passphrase, size_t, int32 $algo, int32 $subalgo,
                    Blob $salt, size_t, uint64 $iterations, size_t,
                    Blob $keybuffer --> int32)
    is native(LIBGCRYPT) {}

sub key-from-passphrase(Any:D $passphrase is copy,
                        Int:D :$keysize,
                        Any:D :$algorithm is copy,
                        Any:D :$subalgorithm is copy,
                        Int:D :$iterations = 1,
                        Any:D :$salt is copy = buf8.new) is export
{
    if $passphrase ~~ Str
    {
        $passphrase = $passphrase.encode
    }

    if $algorithm ~~ Str
    {
        $algorithm = Gcrypt::KDF::{"GCRY_KDF_$algorithm"}
                     // die X::Gcrypt::BadAlgorithm.new(:$algorithm)
    }

    if $subalgorithm ~~ Str
    {
        $subalgorithm = Gcrypt::MD::{"GCRY_MD_$subalgorithm"}
                     // die X::Gcrypt::BadAlgorithm.new(:$algorithm)
    }

    if $salt ~~ Str
    {
        $salt = $salt.encode
    }

    my $key = buf8.allocate($keysize);
    Gcrypt.check: gcry_kdf_derive($passphrase, $passphrase.bytes,
                                  $algorithm, $subalgorithm,
                                  $salt, $salt ?? $salt.bytes !! 0,
                                  $iterations, $keysize, $key);
    $key
}
