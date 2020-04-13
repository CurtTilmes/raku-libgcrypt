use NativeCall;
use Gcrypt;

unit class Gcrypt::MACHandle is repr('CPointer');

method close() is native(LIBGCRYPT)
    is symbol('gcry_mac_close') {}

method setkey(Blob, size_t --> int32)
    is native(LIBGCRYPT) is symbol('gcry_mac_setkey') {}

method setiv(Blob, size_t --> int32)
    is native(LIBGCRYPT) is symbol('gcry_mac_setiv') {}

method control(int32, Blob, size_t)
    is native(LIBGCRYPT) is symbol('gcry_mac_ctl') {}

method write(Blob, size_t --> int32)
    is native(LIBGCRYPT) is symbol('gcry_mac_write') {}

method read(Blob, size_t is rw --> int32)
    is native(LIBGCRYPT) is symbol('gcry_mac_read') {}

method verify(Blob, size_t --> int32)
    is native(LIBGCRYPT) is symbol('gcry_mac_verify') {}
