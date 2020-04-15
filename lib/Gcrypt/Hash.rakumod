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
                      Bool :$hmac,
                      Bool :$bugemu1)
{
    my uint32 $flags = ($hmac    ?? GCRY_MD_FLAG_HMAC    !! 0)
                    +| ($bugemu1 ?? GCRY_MD_FLAG_BUGEMU1 !! 0);

    $!handle .= new;

    Gcrypt.check: gcry_md_open($!handle, $algorithm, $flags);

    $!length = gcry_md_get_algo_dlen($algorithm);

    Gcrypt.check($!handle.setkey($_)) with $key;
}

method clone(--> Gcrypt::Hash)
{
    my Gcrypt::HashHandle $handle .= new;
    Gcrypt.check: gcry_md_copy($handle, $!handle);
    self.bless(:$handle, :$!length)
}

submethod DESTROY()
{
    .close with $!handle;
    $!handle = Nil;
}

method algorithm(--> Gcrypt::MD) { Gcrypt::MD($!handle.algorithm) }

method name(--> Str:D) { gcry_md_algo_name($!handle.algorithm) }

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

method digest(Int $bytes = 0, Bool :$reset --> Blob:D)
{
    my $buf;
    if $!length == 0
    {
        die X::Gcrypt::ExtendedOutput.new(algorithm => $.algorithm)
            unless $bytes > 0;

        $buf = buf8.allocate($bytes);
        Gcrypt.check: $!handle.extract(0, $buf, $bytes);
    }
    else
    {
        $buf = Blob.new: ($!handle.read(0)
                          // die X::Gcrypt::Invalid.new)[^$.length];
    }
    $!handle.reset() if $reset;
    $buf
}

method hex(|opts --> Str:D)
{
    $.digest(|opts)».fmt("%02x").join
}

method dec(|opts --> Int:D)
{
    $.hex(|opts).parse-base(16)
}

=begin pod

=head1 NAME

Gcrypt::Hash - Message Digest / Hashing

=head1 SYNOPSIS

  use Gcrypt::Hash;

  say Gcrypt::Hash.available('MD5');   # True if algorithm ok
  my $obj = Gcrypt::Hash.new(algorithm => 'MD5');
  $obj.write("some data");             # Write Str
  $obj.write(buf8.new(27, 52));        # Write BLob

  say $obj.digest;                     # Blob
  say $obj.hex;                        # hex digit string
  say $obj.dec;                        # Decimal
  say $obj.hex(:reset);                # return hex, and also reset

  $obj.reset;                          # Reuse for another set of data
  my $another = $obj.clone;            # Another copy of same object
  say $obj.algorithm;                  # Algorithm enum
  say $obj.name;                       # Name of algorithm

=head1 DESCRIPTION

Message digest computation.

=head2 METHODS

=item method B<available>($algorithm --> Bool:D)

I<$algorithm> can be a C<Gcrypt::MD> enumeration from C<Gcrypt::Constants>
or a string name of an algorithm.

Check to see if if the algorithm is valid and available for use.

=item method B<new>(:$algorithm)

I<$algorithm> can be a C<Gcrypt::MD> enumeration from C<Gcrypt::Constants>
or a string name of an algorithm.

=item method B<algorithm>(--> Gcrypt::MD)

Returns the C<Gcrypt::MD> enumeration for the algorithm.

=item method B<name>(--> Str:D)

Returns the name of the algorithm.

=item method B<write>($data --> Gcrypt::Hash)

I<$data> can be a C<Blob> or a C<Str> with data to add to the hash
calculation.  Returns the object for convenience.

=item method B<digest>(Int $bytes = 0, Bool :$reset --> Blob:D)

Returns the digest/hash of the data as a C<Blob>.  Some algorithms allow
you to specify an optional I<$bytes> number of bytes to return.

If I<$reset> is included, reset the object for new data.

=item method B<hex>(Int $bytes = 0, Bool :$reset --> Str:D)

Returns the digest/hash of the data as a string of hex digits.

If I<$reset> is included, reset the object for new data.

=item method B<dec>(Int $bytes = 0, Bool :$reset --> Int:D)

Returns the digest/hash of the data as an integer.

If I<$reset> is included, reset the object for new data.

=item submethod B<DESTROY>()

Release the resources for the Hash, called automatically.

=end pod
