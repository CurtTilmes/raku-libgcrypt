enum Gcrypt::Command (
    GCRYCTL_CFB_SYNC                      => 3,
    GCRYCTL_RESET                         => 4,
    GCRYCTL_FINALIZE                      => 5,
    GCRYCTL_GET_KEYLEN                    => 6,
    GCRYCTL_GET_BLKLEN                    => 7,
    GCRYCTL_TEST_ALGO                     => 8,
    GCRYCTL_IS_SECURE                     => 9,
    GCRYCTL_GET_ASNOID                    => 10,
    GCRYCTL_ENABLE_ALGO                   => 11,
    GCRYCTL_DISABLE_ALGO                  => 12,
    GCRYCTL_DUMP_RANDOM_STATS             => 13,
    GCRYCTL_DUMP_SECMEM_STATS             => 14,
    GCRYCTL_GET_ALGO_NPKEY                => 15,
    GCRYCTL_GET_ALGO_NSKEY                => 16,
    GCRYCTL_GET_ALGO_NSIGN                => 17,
    GCRYCTL_GET_ALGO_NENCR                => 18,
    GCRYCTL_SET_VERBOSITY                 => 19,
    GCRYCTL_SET_DEBUG_FLAGS               => 20,
    GCRYCTL_CLEAR_DEBUG_FLAGS             => 21,
    GCRYCTL_USE_SECURE_RNDPOOL            => 22,
    GCRYCTL_DUMP_MEMORY_STATS             => 23,
    GCRYCTL_INIT_SECMEM                   => 24,
    GCRYCTL_TERM_SECMEM                   => 25,
    GCRYCTL_DISABLE_SECMEM_WARN           => 27,
    GCRYCTL_SUSPEND_SECMEM_WARN           => 28,
    GCRYCTL_RESUME_SECMEM_WARN            => 29,
    GCRYCTL_DROP_PRIVS                    => 30,
    GCRYCTL_ENABLE_M_GUARD                => 31,
    GCRYCTL_START_DUMP                    => 32,
    GCRYCTL_STOP_DUMP                     => 33,
    GCRYCTL_GET_ALGO_USAGE                => 34,
    GCRYCTL_IS_ALGO_ENABLED               => 35,
    GCRYCTL_DISABLE_INTERNAL_LOCKING      => 36,
    GCRYCTL_DISABLE_SECMEM                => 37,
    GCRYCTL_INITIALIZATION_FINISHED       => 38,
    GCRYCTL_INITIALIZATION_FINISHED_P     => 39,
    GCRYCTL_ANY_INITIALIZATION_P          => 40,
    GCRYCTL_SET_CBC_CTS                   => 41,
    GCRYCTL_SET_CBC_MAC                   => 42,
    GCRYCTL_ENABLE_QUICK_RANDOM           => 44,
    GCRYCTL_SET_RANDOM_SEED_FILE          => 45,
    GCRYCTL_UPDATE_RANDOM_SEED_FILE       => 46,
    GCRYCTL_SET_THREAD_CBS                => 47,
    GCRYCTL_FAST_POLL                     => 48,
    GCRYCTL_SET_RANDOM_DAEMON_SOCKET      => 49,
    GCRYCTL_USE_RANDOM_DAEMON             => 50,
    GCRYCTL_FAKED_RANDOM_P                => 51,
    GCRYCTL_SET_RNDEGD_SOCKET             => 52,
    GCRYCTL_PRINT_CONFIG                  => 53,
    GCRYCTL_OPERATIONAL_P                 => 54,
    GCRYCTL_FIPS_MODE_P                   => 55,
    GCRYCTL_FORCE_FIPS_MODE               => 56,
    GCRYCTL_SELFTEST                      => 57,
    GCRYCTL_DISABLE_HWF                   => 63,
    GCRYCTL_SET_ENFORCED_FIPS_FLAG        => 64,
    GCRYCTL_SET_PREFERRED_RNG_TYPE        => 65,
    GCRYCTL_GET_CURRENT_RNG_TYPE          => 66,
    GCRYCTL_DISABLE_LOCKED_SECMEM         => 67,
    GCRYCTL_DISABLE_PRIV_DROP             => 68,
    GCRYCTL_SET_CCM_LENGTHS               => 69,
    GCRYCTL_CLOSE_RANDOM_DEVICE           => 70,
    GCRYCTL_INACTIVATE_FIPS_FLAG          => 71,
    GCRYCTL_REACTIVATE_FIPS_FLAG          => 72,
    GCRYCTL_SET_SBOX                      => 73,
    GCRYCTL_DRBG_REINIT                   => 74,
    GCRYCTL_SET_TAGLEN                    => 75,
    GCRYCTL_GET_TAGLEN                    => 76,
    GCRYCTL_REINIT_SYSCALL_CLAMP          => 77,
);

enum Gcrypt::Ciphers (
#    GCRY_CIPHER_NONE        => 0,
    GCRY_CIPHER_IDEA        => 1,
    GCRY_CIPHER_3DES        => 2,
    GCRY_CIPHER_CAST5       => 3,
    GCRY_CIPHER_BLOWFISH    => 4,
#    GCRY_CIPHER_SAFER_SK128 => 5,
#    GCRY_CIPHER_DES_SK      => 6,
    GCRY_CIPHER_AES         => 7,
    GCRY_CIPHER_AES192      => 8,
    GCRY_CIPHER_AES256      => 9,
    GCRY_CIPHER_TWOFISH     => 10,

    GCRY_CIPHER_ARCFOUR     => 301,
    GCRY_CIPHER_DES         => 302,
    GCRY_CIPHER_TWOFISH128  => 303,
    GCRY_CIPHER_SERPENT128  => 304,
    GCRY_CIPHER_SERPENT192  => 305,
    GCRY_CIPHER_SERPENT256  => 306,
    GCRY_CIPHER_RFC2268_40  => 307,
    GCRY_CIPHER_RFC2268_128 => 308,
    GCRY_CIPHER_SEED        => 309,
    GCRY_CIPHER_CAMELLIA128 => 310,
    GCRY_CIPHER_CAMELLIA192 => 311,
    GCRY_CIPHER_CAMELLIA256 => 312,
    GCRY_CIPHER_SALSA20     => 313,
    GCRY_CIPHER_SALSA20R12  => 314,
    GCRY_CIPHER_GOST28147   => 315,
    GCRY_CIPHER_CHACHA20    => 316,
);

enum Gcrypt::CipherMode (
    GCRY_CIPHER_MODE_NONE     => 0,
    GCRY_CIPHER_MODE_ECB      => 1,
    GCRY_CIPHER_MODE_CFB      => 2,
    GCRY_CIPHER_MODE_CBC      => 3,
    GCRY_CIPHER_MODE_STREAM   => 4,
    GCRY_CIPHER_MODE_OFB      => 5,
    GCRY_CIPHER_MODE_CTR      => 6,
    GCRY_CIPHER_MODE_AESWRAP  => 7,
    GCRY_CIPHER_MODE_CCM      => 8,
    GCRY_CIPHER_MODE_GCM      => 9,
    GCRY_CIPHER_MODE_POLY1305 => 10,
    GCRY_CIPHER_MODE_OCB      => 11,
    GCRY_CIPHER_MODE_CFB8     => 12,
    GCRY_CIPHER_MODE_XTS      => 13,
);

enum Gcrypt::CipherFlag (
    GCRY_CIPHER_SECURE      => 1,
    GCRY_CIPHER_ENABLE_SYNC => 2,
    GCRY_CIPHER_CBC_CTS     => 4,
    GCRY_CIPHER_CBC_MAC     => 8
);

enum Gcrypt::Padding < GCRYPT_PADDING_NONE GCRYPT_PADDING_STANDARD
                       GCRYPT_PADDING_NULL GCRYPT_PADDING_SPACE >;

enum Gcrypt::MD (
    GCRY_MD_NONE          => 0,
    GCRY_MD_MD5           => 1,
    GCRY_MD_SHA1          => 2,
    GCRY_MD_RMD160        => 3,
    GCRY_MD_MD2           => 5,
    GCRY_MD_TIGER         => 6,
    GCRY_MD_HAVAL         => 7,
    GCRY_MD_SHA256        => 8,
    GCRY_MD_SHA384        => 9,
    GCRY_MD_SHA512        => 10,
    GCRY_MD_SHA224        => 11,
    GCRY_MD_MD4           => 301,
    GCRY_MD_CRC32         => 302,
    GCRY_MD_CRC32_RFC1510 => 303,
    GCRY_MD_CRC24_RFC2440 => 304,
    GCRY_MD_WHIRLPOOL     => 305,
    GCRY_MD_TIGER1        => 306,
    GCRY_MD_TIGER2        => 307,
    GCRY_MD_GOSTR3411_94  => 308,
    GCRY_MD_STRIBOG256    => 309,
    GCRY_MD_STRIBOG512    => 310,
    GCRY_MD_GOSTR3411_CP  => 311,
    GCRY_MD_SHA3_224      => 312,
    GCRY_MD_SHA3_256      => 313,
    GCRY_MD_SHA3_384      => 314,
    GCRY_MD_SHA3_512      => 315,
    GCRY_MD_SHAKE128      => 316,
    GCRY_MD_SHAKE256      => 317,
    GCRY_MD_BLAKE2B_512   => 318,
    GCRY_MD_BLAKE2B_384   => 319,
    GCRY_MD_BLAKE2B_256   => 320,
    GCRY_MD_BLAKE2B_160   => 321,
    GCRY_MD_BLAKE2S_256   => 322,
    GCRY_MD_BLAKE2S_224   => 323,
    GCRY_MD_BLAKE2S_160   => 324,
    GCRY_MD_BLAKE2S_128   => 325
);

enum Gcrypt::MDFlag (
    GCRY_MD_FLAG_SECURE  => 1,
    GCRY_MD_FLAG_HMAC    => 2,
    GCRY_MD_FLAG_BUGEMU1 => 0x0100
);

enum Gcrypt::MAC::Algorithm (
    GCRY_MAC_NONE               => 0,

    GCRY_MAC_HMAC_SHA256        => 101,
    GCRY_MAC_HMAC_SHA224        => 102,
    GCRY_MAC_HMAC_SHA512        => 103,
    GCRY_MAC_HMAC_SHA384        => 104,
    GCRY_MAC_HMAC_SHA1          => 105,
    GCRY_MAC_HMAC_MD5           => 106,
    GCRY_MAC_HMAC_MD4           => 107,
    GCRY_MAC_HMAC_RMD160        => 108,
    GCRY_MAC_HMAC_TIGER1        => 109,
    GCRY_MAC_HMAC_WHIRLPOOL     => 110,
    GCRY_MAC_HMAC_GOSTR3411_94  => 111,
    GCRY_MAC_HMAC_STRIBOG256    => 112,
    GCRY_MAC_HMAC_STRIBOG512    => 113,
#    GCRY_MAC_HMAC_MD2           => 114,
    GCRY_MAC_HMAC_SHA3_224      => 115,
    GCRY_MAC_HMAC_SHA3_256      => 116,
    GCRY_MAC_HMAC_SHA3_384      => 117,
    GCRY_MAC_HMAC_SHA3_512      => 118,

    GCRY_MAC_CMAC_AES           => 201,
    GCRY_MAC_CMAC_3DES          => 202,
    GCRY_MAC_CMAC_CAMELLIA      => 203,
    GCRY_MAC_CMAC_CAST5         => 204,
    GCRY_MAC_CMAC_BLOWFISH      => 205,
    GCRY_MAC_CMAC_TWOFISH       => 206,
    GCRY_MAC_CMAC_SERPENT       => 207,
    GCRY_MAC_CMAC_SEED          => 208,
    GCRY_MAC_CMAC_RFC2268       => 209,
    GCRY_MAC_CMAC_IDEA          => 210,
    GCRY_MAC_CMAC_GOST28147     => 211,

    GCRY_MAC_GMAC_AES           => 401,
    GCRY_MAC_GMAC_CAMELLIA      => 402,
    GCRY_MAC_GMAC_TWOFISH       => 403,
    GCRY_MAC_GMAC_SERPENT       => 404,
    GCRY_MAC_GMAC_SEED          => 405,

    GCRY_MAC_POLY1305           => 501,
    GCRY_MAC_POLY1305_AES       => 502,
    GCRY_MAC_POLY1305_CAMELLIA  => 503,
    GCRY_MAC_POLY1305_TWOFISH   => 504,
    GCRY_MAC_POLY1305_SERPENT   => 505,
    GCRY_MAC_POLY1305_SEED      => 506
);

enum Gcrypt::MACFlags (
    GCRY_MAC_FLAG_SECURE => 1
);

enum Gcrypt::RandomLevel <
    GCRY_WEAK_RANDOM
    GCRY_STRONG_RANDOM
    GCRY_VERY_STRONG_RANDOM
>;

enum Gcrypt::KDF (
    GCRY_KDF_NONE           => 0,
    GCRY_KDF_SIMPLE_S2K     => 16,
    GCRY_KDF_SALTED_S2K     => 17,
    GCRY_KDF_ITERSALTED_S2K => 19,
    GCRY_KDF_PBKDF2         => 34,
    GCRY_KDF_SCRYPT         => 48
);

enum Gcrypt::GPGError (
     GPG_ERR_CHECKSUM => 10
);
