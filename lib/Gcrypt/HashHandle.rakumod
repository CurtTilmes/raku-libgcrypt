use NativeCall;
use Gcrypt;

unit class Gcrypt::HashHandle is repr('CPointer');

method close() is native(LIBGCRYPT) is symbol('gcry_md_close') {}

method reset() is native(LIBGCRYPT) is symbol('gcry_md_reset') {}

method write(Blob, size_t) is native(LIBGCRYPT) is symbol('gcry_md_write') {}

method read(int32 $algo --> CArray[uint8])
       is native(LIBGCRYPT) is symbol('gcry_md_read') {}

method extract(int32 $algo, Blob:D $buf, size_t $length --> int32)
       is native(LIBGCRYPT) is symbol('gcry_md_extract') {}

method algorithm(--> int32) is native(LIBGCRYPT)is symbol('gcry_md_get_algo') {}

method gcry_md_setkey(Blob, size_t --> int32) is native(LIBGCRYPT) {}

multi method setkey(Blob:D $buf) { $.gcry_md_setkey($buf, $buf.bytes) }

multi method setkey(Str:D $str) { $.setkey($str.encode) }

method is-secure(--> int32)
       is native(LIBGCRYPT) is symbol('gcry_md_is_secure') {}
