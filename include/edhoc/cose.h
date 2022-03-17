#ifndef EDHOC_COSE_H
#define EDHOC_COSE_H

#include <sys/types.h>

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include <stdint.h>
#include <stdlib.h>

#define COSE_ECC_KEY_SIZE           (32)
#define COSE_SYMMETRIC_KEY_SIZE     (16)
#define COSE_MAX_HEADER_ITEMS           (EDHOC_COSE_HEADER_SIZE)

typedef enum {
    COSE_HEADER_PARAM_RESERVED = -65537,
    COSE_HEADER_PARAM_ALG = 1,
    COSE_HEADER_PARAM_CRIT = 2,
    COSE_HEADER_PARAM_CTYPE = 3,
    COSE_HEADER_PARAM_KID = 4,
    COSE_HEADER_PARAM_IV = 5,
    COSE_HEADER_PARAM_X5BAG = 32,
    COSE_HEADER_PARAM_CHAIN = 32,
    COSE_HEADER_PARAM_X5T = 34,
    COSE_HEADER_PARAM_X5U = 35
} cose_hdr_param_t;

/**
 * @brief COSE key types
 */
typedef enum cose_kty {
    COSE_KTY_NONE = 0,         /**< Invalid COSE key */
    COSE_KTY_OCTET = 1,        /**< Octet key pair (eddsa) */
    COSE_KTY_EC2 = 2,          /**< Elliptic curve */
    COSE_KTY_SYMMETRIC = 4,          /**< Elliptic curve */
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
typedef enum cose_algorithm {
    COSE_ALGO_NONE = 0,                     /**< Invalid algo */
    COSE_ALGO_SHA256 = -16,                 /**< SHA-256 */
    COSA_ALGO_SHA256_64 = -15,              /**< SHA-256 truncated to 64 bits */
    COSE_ALGO_EDDSA = -8,                   /**< EdDSA */
    COSE_ALGO_ES256 = -7,                   /**< ECDSA w/ SHA256 */
    COSE_ALGO_AESCCM_16_64_128 = 10,        /**< AES-CCM */
    COSE_ALGO_AESCCM_16_128_128 = 30,       /**< AES-CCM */
} cose_algo_id_t;

typedef enum {
    COSE_KEY_PARAM_KTY = 1,        /**< Key type identifier */
    COSE_KEY_PARAM_KID = 2,        /**< Key identifier */
    COSE_KEY_PARAM_ALGO = 3,       /**< Key algorithm */
    COSE_KEY_PARAM_OPS = 4,        /**< Key options */
    COSE_KEY_PARAM_BIV = 5,        /**< Base IV */
} cose_key_common_param_t;

/**
 * @brief COSE EC2 key parameters
 */
typedef enum {
    COSE_KEY_EC2_PARAM_CRV = -1,    /**< Key type identifier */
    COSE_KEY_EC2_PARAM_X = -2,      /**< Key identifier */
    COSE_KEY_EC2_PARAM_Y = -3,      /**< Key algorithm */
    COSE_KEY_EC2_PARAM_D = -4,      /**< Key options */
} cose_key_ec2_param_t;

typedef enum {
    COSE_PROTECTED_HEADER = 0,
    COSE_UNPROTECTED_HEADER,
} cose_header_type_t;

typedef enum {
    COSE_HDR_VALUE_NONE = 0,
    COSE_HDR_VALUE_INT = 1,
    COSE_HDR_VALUE_BSTR = 2,
    COSE_HDR_VALUE_TSTR = 3,
    COSE_HDR_VALUE_CERTHASH = 4
} cose_hdr_value_type_t;

/**
 * @brief COSE octet key parameters
 */
typedef enum {
    COSE_KEY_OKP_PARAM_CRV = -1,    /**< Key type identifier */
    COSE_KEY_OKP_PARAM_X = -2,      /**< Key identifier */
    COSE_KEY_OKP_PARAM_D = -4,      /**< Key options */
} cose_key_okp_param_t;

typedef struct cose_key_t cose_key_t;
typedef struct cose_encrypt0_t cose_encrypt0_t;
typedef struct cose_sign1_t cose_sign1_t;
typedef struct cose_header_t cose_header_t;
typedef struct cose_cert_hash_t cose_cert_hash_t;
typedef struct cose_message_t cose_message_t;

typedef struct cose_aead_t cose_aead_t;
typedef struct cose_sign_t cose_sign_t;

/**
 * @brief COSE key structure
 */
struct cose_key_t {
    cose_kty_t kty;                     /**< Key type */
    cose_algo_id_t algo;                /**< Key algorithm restriction with this key */
    cose_curve_t crv;                   /**< Curve */
    uint8_t x[COSE_ECC_KEY_SIZE];       /**< Public key */
    size_t xLen;                        /**< Length of the X coordinate of the public key */
    uint8_t y[COSE_ECC_KEY_SIZE];       /**< Public key */
    size_t yLen;                        /**< Length of the Y coordinate of the public key */
    uint8_t d[COSE_ECC_KEY_SIZE];       /**< Private key */
    size_t dLen;                        /**< Length of the private key */
    uint8_t k[COSE_SYMMETRIC_KEY_SIZE];
    size_t kLen;
};

struct cose_aead_t {
    cose_algo_id_t id;
    const char *name;
    uint8_t keyLength;
    uint8_t ivLength;
    uint8_t tagLength;
};

struct cose_sign_t {
    cose_algo_id_t id;
    const char *name;
};

struct cose_cert_hash_t {
    int32_t identifier;
    const uint8_t *value;
    size_t length;
};

struct cose_header_t {
    cose_hdr_param_t key;
    size_t len;
    union {                             /**< Depending on the type, the content is a pointer or an integer */
        int32_t integer;                /**< Direct integer value */
        const uint8_t *bstr;            /**< Pointer to the content */
        const char *tstr;               /**< String type content */
        cose_cert_hash_t certHash;
    };
    cose_hdr_value_type_t valueType;
};

struct cose_message_t {
    cose_header_t protected[COSE_MAX_HEADER_ITEMS];
    uint8_t *payload;
    size_t payloadLen;
    const uint8_t *extAad;
    size_t extAadLen;

};

struct cose_encrypt0_t {
    cose_message_t base;
    uint8_t *authTag;
    const cose_aead_t *aeadCipher;
};

struct cose_sign1_t {
    cose_message_t base;
    const cose_sign_t *signAlgorithm;
    uint8_t *signature;
    size_t sigLen;
};

////////////////////////
// COSE KEY FUNCTIONS //
////////////////////////

/**
 * @brief   Initializes a COSE key object, must be called before using the key
 * object
 *
 * @param[in,out] key      Key object to initialize
 */
void cose_key_init(cose_key_t *key);

/**
 * @brief   Initializes a COSE key from CBOR map
 *
 * @param[in,out] key       Initialized COSE key to populate
 * @param[in] in            Input buffer holding a CBOR-encoded COSE key
 * @param[in] ilen          Length of @p in
 *
 * @return  On success return EDHOC_SUCCESS
 * @return  On failure a negative value
 */
int cose_key_from_cbor(cose_key_t *key, const uint8_t *in, size_t ilen);

/**
 *
 * @param key
 * @param k
 * @param kLen
 * @return
 */
int cose_symmetric_key_from_buffer(cose_key_t *key, uint8_t *k, size_t kLen);

///////////////////////////
// COSE HEADER FUNCTIONS //
///////////////////////////

/**
 * @brief Initializes a COSE header map
 *
 * @param header
 */
void cose_header_init(cose_header_t *header);

/**
 * @brief Parse a COSE header map
 *
 * @param header
 * @param in
 * @param ilen
 * @return
 */
int cose_header_parse(cose_header_t *header, const uint8_t *in, size_t ilen);

/**
 *
 * @param header
 * @param out
 * @param olen
 * @return
 */
int cose_header_serialize(cose_header_t *header, uint8_t *out, size_t olen);

/**
 *
 * @param header
 * @return
 */
ssize_t cose_header_serialized_len(cose_header_t *header);

////////////////////////////
// COSE MESSAGE FUNCTIONS //
////////////////////////////

/**
 *
 * @param coseMsgCtx
 * @param header
 */
int cose_message_set_protected_hdr(cose_message_t *coseMsgCtx, cose_header_t *header);

/**
 *
 * @param coseMsgCtx
 * @param extAad
 * @param extAadLen
 */
void cose_message_set_external_aad(cose_message_t *coseMsgCtx, const uint8_t *extAad, size_t extAadLen);

/**
 *
 * @param coseMsgCtx
 * @param payload
 * @param len
 */
void cose_message_set_payload(cose_message_t *coseMsgCtx, const uint8_t *payload, size_t len);

/**
 *
 * @param encrypt0Ctx
 * @param algo
 */
void cose_message_set_algo(cose_message_t *coseMsgCtx, cose_algo_id_t);

/**
 *
 * @param coseMsgCtx
 * @param symmetric
 * @param out
 * @param olen
 * @return
 */
ssize_t cose_encrypt0_encrypt(cose_encrypt0_t *coseMsgCtx, const cose_key_t *key, const uint8_t *iv, size_t ivLen);

/**
 * @brief Initializes a COSE Encrypt0 context
 *
 * @param coseMsgCtx
 */
void cose_encrypt0_init(cose_encrypt0_t *coseMsgCtx,
                        uint8_t *payload,
                        size_t payloadLen,
                        const cose_aead_t *aeadCipher,
                        uint8_t *tag);

/**
 *
 * @param coseMsgCtx
 * @param payload
 * @param payloadLen
 * @param algo
 * @param tag
 */
void cose_sign1_init(cose_sign1_t *coseMsgCtx,
                     uint8_t *payload,
                     size_t payloadLen,
                     const cose_sign_t *algo,
                     uint8_t *signature);

/**
 *
 * @param coseMsgCtx
 * @param key
 * @return
 */
ssize_t cose_sign1_sign(cose_sign1_t *coseMsgCtx, const cose_key_t *key);

/**
 *
 * @param coseMsgCtx
 * @param key
 * @return
 */
ssize_t cose_sign1_verify(cose_sign1_t *coseMsgCtx, const cose_key_t *key);

/**
 *
 * @param coseMsgCtx
 * @param label
 * @param out
 * @param olen
 * @return
 */
ssize_t cose_encrypt0_create_adata(cose_encrypt0_t *coseMsgCtx, uint8_t *out, size_t olen);

/**
 *
 * @param coseMsgCtx
 * @param key
 * @param iv
 * @param ivLen
 * @return
 */
ssize_t cose_encrypt0_decrypt(cose_encrypt0_t *coseMsgCtx, const cose_key_t *key, const uint8_t *iv, size_t ivLen);

/**
 *
 * @param coseMsgCtx
 * @param out
 * @param olen
 * @return
 */
ssize_t cose_sign1_create_to_be_signed(cose_sign1_t *coseMsgCtx, uint8_t *out, size_t olen);

/////////////////////
// COSE ALGORITHMS //
/////////////////////

/**
 *
 * @param id
 * @return
 */
const cose_aead_t *cose_algo_get_aead_info(cose_algo_id_t id);

/**
 *
 * @param id
 * @return
 */
const cose_sign_t *cose_algo_get_sign_info(cose_algo_id_t id);


#endif /* EDHOC_COSE_H */
