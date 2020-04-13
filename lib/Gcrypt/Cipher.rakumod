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

multi method available(Int:D $algorithm --> Bool:D)
{
    gcry_cipher_algo_info($algorithm, GCRYCTL_TEST_ALGO, Blob, 0) == 0;
}

multi method available(Str:D $algorithm --> Bool:D)
{
    samewith gcry_cipher_map_name($algorithm) || return False;
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
                Bool :$!bin,
                )
{
    die X::Gcrypt::BadAlgorithm.new(:$!algorithm)
        unless Gcrypt::Cipher.available($!algorithm);

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

submethod DESTROY()
{
    .close with $!handle;
    $!handle = Nil;
}

multi method encrypt(Blob:D $in where *.bytes %% $!blklen --> Blob)
{
    my $out = buf8.allocate($in.bytes);
    Gcrypt.check: $!handle.encrypt($out, $out.bytes, $in, $in.bytes);
    $out
}

multi method encrypt(Blob:D $in where !(*.bytes %% $!blklen))
{
    samewith Buf.new($in).append(0 xx $!blklen - $in.bytes % $!blklen)
}

multi method encrypt(Str:D $in --> Blob)
{
    samewith $in.encode
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

method name(--> Str:D)
{
    gcry_cipher_algo_name($!algorithm)
}

method reset()
{
    Gcrypt.check: $!handle.control(GCRYCTL_RESET, Pointer, 0);
    self
}

=begin pod

=head1 NAME

Gcrypt::Cipher - Symmetric cryptography ciphers

=head1 SYNOPSIS

  use Gcrypt::Cipher;

  my $obj = Gcrypt::Cipher.new(algorithm => 'IDEA',
                               key => 'my-key');

  my $encrypted = $obj.encrypt('something');

  $obj.reset;

  print $obj.decrypt($encrypted);

=head1 DESCRIPTION

Cryptography using a shared key.

=head2 METHODS

=item method B<available>(Str:D $algorithm --> Bool:D)

Returns C<True> if the algorithm is valid.  Can run with undefined
object, C<Gcrypt::Cipher.available('DES')>.

=item method B<new>(:$algorithm, :$key, :$iv, :$mode, Bool :$bin)

I<$algorithm> can be a B<Str>, or one of C<GCrypt::Ciphers> from
C<Gcrypt::Constants>.

I<$key> can be a B<Str> or a B<Blob>.

I<$mode> can be a B<Str>, or one of C<Gcrypt::CipherMode> from
C<Gcrypt::Constants>.  It defaults to 'CBC' for block ciphers and
'STREAM' for stream ciphers.  [ Modes not extensively tested, file
issues if anything doesn't work the way it seems like it should! ]

I<$iv> is an optional initialization vector, and can be a B<Str> or a
B<Blob>.  Usefulness depends on algorithm and mode.

I<$bin> will set the default for B<decrypt> to return B<Blob>s instead
of B<Str>s.

=item method B<blklen>(--> Int)

Return the block length for the selected algorithm

=item method B<keylen>(--> size_t)

Return the key length for the selected algorithm.

=item method B<name>(--> Str:D)

Returns the name of the algorithm.

=item method B<setkey>($key)

I<$key> can be a B<Str> or a B<Blob>.  The key is truncated or 0
extended to match the key length for the algorithm.  Some algorithms
will reject weak keys with an exception.

=item method B<setiv>($iv)

I<$iv> can be a B<Str> or a B<Blob>.  The initialization vector is
truncated or 0 exteneded to match the block length for the algorithm.

=item method B<encrypt>($in)

I<$in> can be a B<Str> or a B<Blob>.

Always returns a B<Blob>

=item method B<decrypt>(Blob:D $in Bool :$bin)

I<$in> is the encrypted B<Blob>.

Returns either a B<Blob> if I<$bin> is True or decodes to a B<Str>.

=item method B<reset>()

Resets the state and clears the initialization vector.

=item submethod B<DESTROY>()

Release the resources for the Cipher, called automatically.

=end pod
