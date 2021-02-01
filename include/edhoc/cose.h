#ifndef EDHOC_COSE_H
#define EDHOC_COSE_H

#include <stdint.h>
#include <stdlib.h>

#define COSE_MAX_KEY_LEN        (32)
#define COSE_MAX_IV_LEN         (16)
#define COSE_DIGEST_LEN         (32)
#define COSE_MAX_TAG_LEN        (16)
#define COSE_MAX_SIGNATURE_LEN  (64)

#define COSE_MAX_KID_LEN        (8)
#define COSE_NUM_KEY_OPS        (5)

typedef enum {
    COSE_KEY_COMMON_PARAM_KTY = 1,        /**< Key type identifier */
    COSE_KEY_COMMON_PARAM_KID = 2,        /**< Key identifier */
    COSE_KEY_COMMON_PARAM_ALGO = 3,       /**< Key algorithm */
    COSE_KEY_COMMON_PARAM_OPS = 4,        /**< Key options */
    COSE_KEY_COMMON_PARAM_BIV = 5,        /**< Base IV */
    COSE_KEY_COMMON_PARAM_X5CHAIN = 33,   /**< An ordered chain of X.509 certificates */
    COSE_KEY_COMMON_PARAM_X5T = 34,       /**< Hash of an X.509 certificate */
    COSE_KEY_COMMON_PARAM_URI = 35,       /**< URI pointing to an X.509 certificate */
} cose_key_common_param_t;

/**
 * @brief COSE EC2 key parameters
 */
typedef enum {
    COSE_KEY_EC2_PARAM_CRV = -1,    /**< Key type identifier */
    COSE_KEY_EC2_PARAM_X = -2,      /**< Key identifier */
    COSE_KEY_EC2_PARAM_Y = -3,      /**< Key algorithm */
    COSE_KEY_EC2_PARAM_D = -4,      /**< Key options */
} COSE_key_ec2_param_t;

/**
 * @brief COSE octet key parameters
 */
typedef enum {
    COSE_KEY_OKP_PARAM_CRV = -1,    /**< Key type identifier */
    COSE_KEY_OKP_PARAM_X = -2,      /**< Key identifier */
    COSE_KEY_OKP_PARAM_D = -4,      /**< Key options */
} cose_key_okp_param_t;

/**
 * @brief COSE symmetric key parameters
 */
typedef enum {
    COSE_KEY_SYMMETRIC_PARAM_K = -4,    /**< Key type identifier */
} COSE_key_symmetric_param_t;

/**
 * @brief COSE key types
 */
typedef enum cose_kty {
    COSE_KTY_NONE = 0,         /**< Invalid COSE key */
    COSE_KTY_OCTET = 1,        /**< Octet key pair (eddsa) */
    COSE_KTY_EC2 = 2,          /**< Elliptic curve */
    COSE_KTY_SYMM = 4,         /**< Symmetric key types */
} cose_kty_t;

/**
 * @brief COSE curve numbers
 */
typedef enum cose_curve {
    COSE_EC_NONE = 0,                /**< Not an EC key */
    COSE_EC_CURVE_P256 = 1,          /**< secp256r1 */
    COSE_EC_CURVE_X25519 = 4,        /**< X25519, ECDH only */
    COSE_EC_CURVE_ED25519 = 6,       /**< Ed25519 for EdDSA only */
} cose_curve_t;

/**
 * @brief COSE algorithm numbers
 */
typedef enum cose_algo {
    COSE_ALGO_NONE = 0,                     /**< Invalid algo */
    COSE_ALGO_SHA256 = -16,                 /**< SHA-256 */
    COSE_ALGO_SHA256_64 = -15,              /**< SHA-256 truncated to 64 bits */
    COSE_ALGO_EDDSA = -8,                   /**< EdDSA */
    COSE_ALGO_ES256 = -7,                   /**< ECDSA w/ SHA256 */
    COSE_ALGO_AESCCM_16_64_128 = 10,        /**< AES-CCM */
    COSE_ALGO_AESCCM_16_128_128 = 30,       /**< AES-CCM */
} cose_algo_t;

/**
 * COSE Key structure
 */
typedef struct cose_key {
    cose_kty_t kty;                     /**< Key type */
    cose_algo_t algo;                   /**< Key algorithm restriction with this key */
    uint8_t kid[COSE_MAX_KID_LEN];      /**< Key identifier */
    size_t kid_len;                     /**< Length of the key identifier */
    uint8_t key_ops[COSE_NUM_KEY_OPS];  /**< Allowed key operations */
    cose_curve_t crv;                   /**< Curve, algo is derived from this for now */
    uint8_t x[COSE_MAX_KEY_LEN];        /**< X coordinate of the public key */
    size_t x_len;                       /**< Length of the X coordinate of the public key */
    uint8_t y[COSE_MAX_KEY_LEN];        /**< Y coordinate of the public key, meaningless in case ok COSE_KTY_OCTET */
    size_t y_len;                       /**< Length of the Y coordinate of the public key */
    uint8_t d[COSE_MAX_KEY_LEN];        /**< Private or secret key */
    size_t d_len;                       /**< Length of the private key */
    uint8_t k[COSE_MAX_KEY_LEN];        /**< Symmetric secret key */
    size_t k_len;                       /**< Length of the symmetric secret key */
} cose_key_t;


/**
 * @brief   Initializes a COSE key object, must be called before using the key
 * object
 *
 * @param[in,out] key      Key object to initialize
 */
void cose_key_init(cose_key_t *key);

/**
 * @brief   Initializes a key struct based on a cbor map
 *
 * @param[out] key          Initialized COSE key struct to fill with key information
 * @param[in] key_bytes     Array of bytes containing the CBOR encoded key
 * @param[in] key_len       Length of @p key_bytes
 *
 * @return  On success return EDHOC_SUCCESS
 * @return  On failure a negative value
 */
int cose_key_from_cbor(cose_key_t *key, const unsigned char *key_bytes, size_t key_len);

/*
 * @brief Get the key length for a specific COSE algorithm identifier
 *
 * @param[in]   alg     An COSE algorithm
 *
 * @return  On success the length of the key used with this algorithm
 * @return  On failure a negative value
 */
int cose_key_len_from_alg(cose_algo_t alg);

/**
 * @brief Get the IV length for a specific COSE algorithm identifier
 *
 * @param[in]   alg     An COSE algorithm
 *
 * @return  On success the length of the IV used with this algorithm
 * @return  On failure a negative value
 */
int cose_iv_len_from_alg(cose_algo_t alg);

/**
 * @brief Get the authentication tag length for a specific COSE algorithm identifier
 *
 * @param[in]   alg     An COSE algorithm
 *
 * @return  On success the length of the authentication tag used with this algorithm
 * @return  On failure a negative value
 */
int cose_tag_len_from_alg(cose_algo_t alg);

/**
 * @brief Create a COSE header attribute for hash-based certificate identification
 *
 * @param[in]   hash        COSE hash algorithm used to create a digest from the certificate
 * @param[in]   cert        Pointer to the certificate
 * @param[in]   cert_len    Total length of the certificate
 * @param[out]  out         The output buffer, will contain the CBOR encoded X5T attribute
 * @param[in]   olen        Total size of @p out
 *
 * @return On success the length of the CBOR encoded header attribute
 * @return On failure a negative value
 */
ssize_t cose_x5t_attribute(cose_algo_t hash, const uint8_t *cert, size_t cert_len, uint8_t *out, size_t olen);


#endif /* EDHOC_COSE_H */
