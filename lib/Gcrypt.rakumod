use NativeCall;
use NativeLibs;
use Gcrypt::Constants;

sub LIBGCRYPT is export
{
    NativeLibs::Searcher.at-runtime(
    'gcrypt',
    'gcry_check_version',
    20).()
}

sub gcry_check_version(Str $req_version --> Str) is native(LIBGCRYPT) {}

sub gcry_get_config(int32, Str --> Pointer)
    is native(LIBGCRYPT) {}

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
    method init(Str :$version = '1.7.6', Int :$secmem --> Str:D)
    {
        return if gcry_control0(GCRYCTL_INITIALIZATION_FINISHED_P);

        die X::Gcrypt::BadVersion.new unless gcry_check_version($version);

        if $secmem
        {
            $.control: GCRYCTL_SUSPEND_SECMEM_WARN;
            $.control: GCRYCTL_INIT_SECMEM, $secmem;
            $.control: GCRYCTL_RESUME_SECMEM_WARN;
        }
        else
        {
            $.control: GCRYCTL_DISABLE_SECMEM;
        }

        $.control: GCRYCTL_INITIALIZATION_FINISHED;
        return gcry_check_version(Str)
    }

    multi method check(0) { 0 }
    multi method check($code) { die X::Gcrypt.new(:$code) }

    method config(Str $what?)
    {
        my $ptr = gcry_get_config(0, $what) // die X::Gcrypt.new;
        my $str = nativecast(Str, $ptr);
        gcry_free($ptr);
        $str
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
