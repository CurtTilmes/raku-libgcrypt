use NativeCall;
use Gcrypt;

unit class Gcrypt::CipherHandle is repr('CPointer');

method close() is native(LIBGCRYPT) is symbol('gcry_cipher_close') {}

method setkey(Blob, size_t --> int32)
    is native(LIBGCRYPT) is symbol('gcry_cipher_setkey') {}

method setiv(Blob, size_t --> int32)
    is native(LIBGCRYPT) is symbol('gcry_cipher_setiv') {}

method encrypt(Blob $out, size_t $outsize, Blob $in, size_t $inlen --> int32)
    is native(LIBGCRYPT) is symbol('gcry_cipher_encrypt') {}

method decrypt(Blob $out, size_t $outsize, Blob $in, size_t $inlen --> int32)
    is native(LIBGCRYPT) is symbol('gcry_cipher_decrypt') {}

method control(int32 $cmd, Pointer $ptr, size_t $buflen --> int32)
    is native(LIBGCRYPT) is symbol('gcry_cipher_ctl') {}
