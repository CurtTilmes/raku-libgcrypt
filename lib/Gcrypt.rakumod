use NativeCall;
use NativeLibs:ver<0.0.7>:auth<github:salortiz>;
use Gcrypt::Constants;

sub LIBGCRYPT is export
{
    NativeLibs::Searcher.at-runtime(
    'gcrypt',
    'gcry_check_version',
    20).()
}

sub gcry_check_version(Str $req_version --> Str) is native(LIBGCRYPT) {}

sub gcry_free(Pointer)
    is native(LIBGCRYPT) {}

sub gcry_control0(uint32 $cmd --> uint32)
    is native(LIBGCRYPT) is symbol('gcry_control') {}
sub gcry_control1(uint32 $cmd, uint32 --> uint32)
    is native(LIBGCRYPT) is symbol('gcry_control') {}
sub gcry_control2(uint32 $cmd, uint32, uint32 --> uint32)
    is native(LIBGCRYPT) is symbol('gcry_control') {}

class X::Gcrypt is Exception
{
    has uint32 $.code;

    sub gcry_strsource(uint32 $err --> Str) is native(LIBGCRYPT) {}
    sub gcry_strerror(uint32 $err --> Str) is native(LIBGCRYPT) {}

    method message()
    {
        "Failure: {gcry_strsource($!code)}/{gcry_strerror($!code)}"
    }
}

class X::Gcrypt::BadVersion is X::Gcrypt
{
    method message()
    {
        'Incompatible libgcrypt version: ' ~ gcry_check_version(Str)
    }
}

class X::Gcrypt::NoHandle is X::Gcrypt
{
    method message() { 'No handle' }
}

class X::Gcrypt::Invalid is X::Gcrypt
{
    method message() { 'Invalid' }
}

class X::Gcrypt::BadMode is X::Gcrypt
{
    has Str $.mode;
    method message() { "Unknown Cipher Mode $!mode" }
}

class X::Gcrypt::BadFormat is X::Gcrypt
{
    has Str $.format;
    method message() { "Unknown Format $!format" }
}

class X::Gcrypt::BadAlgorithm is X::Gcrypt
{
    has Str $.algorithm;
    method message() { "Unknown Algorithm $!algorithm" }
}

class X::Gcrypt::ExtendedOutput is X::Gcrypt
{
    has Str $.algorithm;
    method message() { "$!algorithm has extended output, request digest size" }
}

class Gcrypt
{
    method version(--> Str:D) { gcry_check_version(Str) }

    multi method check(0) { 0 }
    multi method check($code) { die X::Gcrypt.new(:$code) }

    sub gcry_get_config(int32, Str --> Pointer)
    is native(LIBGCRYPT) {}

    method config(Str $what? --> Str:D)
    {
        try  # Intermittent return of garbage characters that break utf-8
        {
            my $ptr = gcry_get_config(0, $what) // die;
            my $str = nativecast(Str, $ptr);
            gcry_free($ptr);
            return $str
        }
        return "Unknown configuration" if $!;
    }

    multi method control(Gcrypt::Command:D $cmd)
    {
        $.check: gcry_control0($cmd)
    }

    multi method control(Gcrypt::Command:D $cmd, Int:D $arg1)
    {
        $.check: gcry_control1($cmd, $arg1)
    }

    multi method control(Gcrypt::Command:D $cmd, Int:D $arg1, Int:D $arg2)
    {
        $.check: gcry_control2($cmd, $arg2)
    }
}

INIT
{
    Gcrypt.version;
    Gcrypt.control: GCRYCTL_DISABLE_SECMEM, 0;
    Gcrypt.control: GCRYCTL_INITIALIZATION_FINISHED, 0;
}

=begin pod

=head1 NAME

Gcrypt - Raku bindings for GNU libgrypt

=head1 SYNOPSIS

  use Gcrypt;
  say Gcrypt.version;             # String like '1.7.6beta' or '1.8.1' ...
  say Gcrypt.config;              # Text dump of config information
  say Gcrypt.config('ciphers');   # Just ciphers
  say Gcrypt.config('digests');   # Just digests, ...

  Gcrypt.control($cmd, ...);      # Various control stuff you don't need
  Gcrypt.check(...);              # Error check internal libgcrypt call

=head1 DESCRIPTION

Top-level module for Gcrypt, bindings to the [GNU libgcrypt](
https://gnupg.org/software/libgcrypt) library.

It defines some exceptions and wraps some top-level routines for
initialization, configuration, and control.

Generally you want to use one of the other C<Gcrypt::*> modules
instead of this.

=head2 METHODS

=item method B<version>(Str :$version, Int :$secmem --> Str:D)

Returns the version string for the library.

=item method B<config>(Str $what?)

Returns some configuration information.  $what can be 'ciphers',
'digests', or other configuration items listed in config.

=item method B<control>(Gcrypt::Command:D $cmd, ...)

Used to control some internal aspects of the library.

=item method B<check>(Int $code)

Throws an exception on anything but 0, used to check library returns.

=end pod
