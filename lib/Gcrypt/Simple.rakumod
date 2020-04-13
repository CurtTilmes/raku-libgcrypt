use Gcrypt::Constants;
use Gcrypt::Cipher;
use Gcrypt::Hash;
use Gcrypt::MAC;

sub IDEA($key, |opts) is export(:IDEA)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_IDEA, :$key, |opts)
}

sub DES3($key, |opts) is export(:DES3)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_3DES, :$key, |opts)
}

sub CAST5($key, |opts) is export(:CAST5)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_CAST5, :$key, |opts)
}

sub Blowfish($key, |opts) is export(:Blowfish)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_BLOWFISH, :$key, |opts)
}

sub AES($key, |opts) is export(:AES)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_AES, :$key, |opts)
}

sub AES192($key, |opts) is export(:AES192)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_AES192, :$key, |opts)
}

sub AES256($key, |opts) is export(:AES256)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_AES256, :$key, |opts)
}

sub Twofish($key, |opts) is export(:Twofish)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_TWOFISH, :$key, |opts)
}

sub RC4($key, |opts) is export(:RC4)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_ARCFOUR, :$key, |opts)
}

sub DES($key, |opts) is export(:DES)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_DES, :$key, |opts)
}

sub Twofish128($key, |opts) is export(:Twofish128)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_TWOFISH128, :$key, |opts)
}

sub Serpent128($key, |opts) is export(:Serpent128)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_SERPENT128, :$key, |opts)
}

sub Serpent192($key, |opts) is export(:Serpent192)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_SERPENT192, :$key, |opts)
}

sub Serpent256($key, |opts) is export(:Serpent256)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_SERPENT256, :$key, |opts)
}

sub RFC2268_40($key, |opts) is export(:RFC2268_40)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_RFC2268_40, :$key, |opts)
}

sub RFC2268_128($key, |opts) is export(:RFC2268_128)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_RFC2268_128, :$key, |opts)
}

sub SEED($key, |opts) is export(:SEED)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_SEED, :$key, |opts)
}

sub Camellia128($key, |opts) is export(:Camellia128)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_CAMELLIA128, :$key, |opts)
}

sub Camellia192($key, |opts) is export(:Camellia192)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_CAMELLIA192, :$key, |opts)
}

sub Camellia256($key, |opts) is export(:Camellia256)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_CAMELLIA256, :$key, |opts)
}

sub Salsa20($key, |opts) is export(:Salsa20)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_SALSA20, :$key, |opts)
}

sub Salsa20R12($key, |opts) is export(:Salsa20R12)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_SALSA20R12, :$key, |opts)
}

sub GOST28147($key, |opts) is export(:GOST28147)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_GOST28147, :$key, |opts)
}

sub ChaCha20($key, |opts) is export(:ChaCha20)
{
    Gcrypt::Cipher.new(algorithm => GCRY_CIPHER_CHACHA20, :$key, |opts)
}

#----------------------------------------------------------------------

sub MD5($data?, |opts) is export(:MD5)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_MD5, |opts).write($data)
}

sub SHA1($data?, |opts) is export(:SHA1)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA1, |opts).write($data)
}

sub RIPEMD160($data?, |opts) is export(:RIPEMD160)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_RMD160, |opts).write($data)
}

sub TIGER($data?, |opts) is export(:TIGER)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_TIGER, |opts).write($data)
}

sub SHA256($data?, |opts) is export(:SHA256)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA256, |opts).write($data)
}

sub SHA384($data?, |opts) is export(:SHA384)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA384, |opts).write($data)
}

sub SHA512($data?, |opts) is export(:SHA512)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA512, |opts).write($data)
}

sub SHA224($data?, |opts) is export(:SHA224)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA224, |opts).write($data)
}

sub MD4($data?, |opts) is export(:MD4)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_MD4, |opts).write($data)
}

sub CRC32($data?, |opts) is export(:CRC32)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_CRC32, |opts).write($data)
}

sub CRC32_RFC1510($data?, |opts) is export(:CRC32_RFC1510)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_CRC32_RFC1510, |opts).write($data)
}

sub CRC24_RFC2440($data?, |opts) is export(:CRC24_RFC2440)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_CRC24_RFC2440, |opts).write($data)
}

sub WHIRLPOOL($data?, |opts) is export(:WHIRLPOOL)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_WHIRLPOOL, |opts).write($data)
}

sub TIGER1($data?, |opts) is export(:TIGER1)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_TIGER1, |opts).write($data)
}

sub TIGER2($data?, |opts) is export(:TIGER2)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_TIGER2, |opts).write($data)
}

sub GOSTR3411_94($data?, |opts) is export(:GOSTR3411_94)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_GOSTR3411_94, |opts).write($data)
}

sub STRIBOG256($data?, |opts) is export(:STRIBOG256)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_STRIBOG256, |opts).write($data)
}

sub STRIBOG512($data?, |opts) is export(:STRIBOG512)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_STRIBOG512, |opts).write($data)
}

sub SHA3_224($data?, |opts) is export(:SHA3_224)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA3_224, |opts).write($data)
}

sub SHA3_256($data?, |opts) is export(:SHA3_256)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA3_256, |opts).write($data)
}

sub SHA3_384($data?, |opts) is export(:SHA3_384)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA3_384, |opts).write($data)
}

sub SHA3_512($data?, |opts) is export(:SHA3_512)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHA3_512, |opts).write($data)
}

sub SHAKE128($data?, |opts) is export(:SHAKE128)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHAKE128, |opts).write($data)
}

sub SHAKE256($data?, |opts) is export(:SHAKE256)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_SHAKE256, |opts).write($data)
}

sub BLAKE2B_512($data?, |opts) is export(:BLAKE2B_512)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2B_512, |opts).write($data)
}

sub BLAKE2B_384($data?, |opts) is export(:BLAKE2B_384)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2B_384, |opts).write($data)
}

sub BLAKE2B_256($data?, |opts) is export(:BLAKE2B_256)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2B_256, |opts).write($data)
}

sub BLAKE2B_160($data?, |opts) is export(:BLAKE2B_160)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2B_160, |opts).write($data)
}

sub BLAKE2S_256($data?, |opts) is export(:BLAKE2S_256)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2S_256, |opts).write($data)
}

sub BLAKE2S_224($data?, |opts) is export(:BLAKE2S_224)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2S_224, |opts).write($data)
}

sub BLAKE2S_160($data?, |opts) is export(:BLAKE2S_160)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2S_160, |opts).write($data)
}

sub BLAKE2S_128($data?, |opts) is export(:BLAKE2S_128)
{
    Gcrypt::Hash.new(algorithm => GCRY_MD_BLAKE2S_128, |opts).write($data)
}

#----------------------------------------------------------------------

sub HMAC_SHA256($key, $data?, |opts) is export(:HMAC_SHA256)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA256, :$key, |opts).write($data)
}

sub HMAC_SHA224($key, $data?, |opts) is export(:HMAC_SHA224)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA224, :$key, |opts).write($data)
}

sub HMAC_SHA512($key, $data?, |opts) is export(:HMAC_SHA512)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA512, :$key, |opts).write($data)
}

sub HMAC_SHA384($key, $data?, |opts) is export(:HMAC_SHA384)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA384, :$key, |opts).write($data)
}

sub HMAC_SHA1($key, $data?, |opts) is export(:HMAC_SHA1)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA1, :$key, |opts).write($data)
}

sub HMAC_MD5($key, $data?, |opts) is export(:HMAC_MD5)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_MD5, :$key, |opts).write($data)
}

sub HMAC_MD4($key, $data?, |opts) is export(:HMAC_MD4)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_MD4, :$key, |opts).write($data)
}

sub HMAC_RIPEMD160($key, $data?, |opts) is export(:HMAC_RIPEMD160)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_RMD160, :$key, |opts).write($data)
}

sub HMAC_TIGER($key, $data?, |opts) is export(:HMAC_TIGER)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_TIGER1, :$key, |opts).write($data)
}

sub HMAC_WHIRLPOOL($key, $data?, |opts) is export(:HMAC_WHIRLPOOL)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_WHIRLPOOL, :$key, |opts)
        .write($data)
}

sub HMAC_GOSTR3411_94($key, $data?, |opts) is export(:HMAC_GOSTR3411_94)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_GOSTR3411_94, :$key, |opts)
        .write($data)
}

sub HMAC_STRIBOG256($key, $data?, |opts) is export(:HMAC_STRIBOG256)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_STRIBOG256, :$key, |opts)
        .write($data)
}

sub HMAC_STRIBOG512($key, $data?, |opts) is export(:HMAC_STRIBOG512)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_STRIBOG512, :$key, |opts)
        .write($data)
}

sub HMAC_SHA3_224($key, $data?, |opts) is export(:HMAC_SHA3_224)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA3_224, :$key, |opts)
        .write($data)
}

sub HMAC_SHA3_256($key, $data?, |opts) is export(:HMAC_SHA3_256)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA3_256, :$key, |opts)
        .write($data)
}

sub HMAC_SHA3_384($key, $data?, |opts) is export(:HMAC_SHA3_384)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA3_384, :$key, |opts)
        .write($data)
}

sub HMAC_SHA3_512($key, $data?, |opts) is export(:HMAC_SHA3_512)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_HMAC_SHA3_512, :$key, |opts)
        .write($data)
}

sub CMAC_AES($key, $data?, |opts) is export(:CMAC_AES)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_AES, :$key, |opts)
        .write($data)
}

sub CMAC_3DES($key, $data?, |opts) is export(:CMAC_3DES)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_3DES, :$key, |opts)
        .write($data)
}

sub CMAC_Camellia($key, $data?, |opts) is export(:CMAC_Camellia)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_CAMELLIA, :$key, |opts)
        .write($data)
}

sub CMAC_CAST5($key, $data?, |opts) is export(:CMAC_CAST5)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_CAST5, :$key, |opts)
        .write($data)
}

sub CMAC_Blowfish($key, $data?, |opts) is export(:CMAC_Blowfish)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_BLOWFISH, :$key, |opts)
        .write($data)
}

sub CMAC_Twofish($key, $data?, |opts) is export(:CMAC_Twofish)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_TWOFISH, :$key, |opts)
        .write($data)
}

sub CMAC_Serpent($key, $data?, |opts) is export(:CMAC_Serpent)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_SERPENT, :$key, |opts)
        .write($data)
}

sub CMAC_SEED($key, $data?, |opts) is export(:CMAC_SEED)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_SEED, :$key, |opts)
        .write($data)
}

sub CMAC_RFC2268($key, $data?, |opts) is export(:CMAC_RFC2268)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_RFC2268, :$key, |opts)
        .write($data)
}

sub CMAC_IDEA($key, $data?, |opts) is export(:CMAC_IDEA)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_IDEA, :$key, |opts)
        .write($data)
}

sub CMAC_GOST28147($key, $data?, |opts) is export(:CMAC_GOST28147)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_CMAC_GOST28147, :$key, |opts)
        .write($data)
}

sub GMAC_AES($key, $data?, |opts) is export(:GMAC_AES)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_GMAC_AES, :$key, |opts)
        .write($data)
}

sub GMAC_Camellia($key, $data?, |opts) is export(:GMAC_Camellia)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_GMAC_CAMELLIA, :$key, |opts)
        .write($data)
}

sub GMAC_Twofish($key, $data?, |opts) is export(:GMAC_Twofish)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_GMAC_TWOFISH, :$key, |opts)
        .write($data)
}

sub GMAC_Serpent($key, $data?, |opts) is export(:GMAC_Serpent)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_GMAC_SERPENT, :$key, |opts)
        .write($data)
}

sub GMAC_SEED($key, $data?, |opts) is export(:GMAC_SEED)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_GMAC_SEED, :$key, |opts)
        .write($data)
}

sub POLY1305($key, $data?, |opts) is export(:POLY1305)
{
    Gcrypt::MAC.new(algorithm => GCRY_MAC_POLY1305, :$key, |opts)
        .write($data)
}
