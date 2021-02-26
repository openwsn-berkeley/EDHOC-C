#ifndef EDHOC_EDHOC_H
#define EDHOC_EDHOC_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/**
 * @brief Definitions for internal buffer sizes
 */
#if !defined(EDHOC_CID_MAX_LEN)
#define EDHOC_CID_MAX_LEN                           (4)
#endif

#if !defined(EDHOC_CREDENTIAL_MAX_SIZE)
#define EDHOC_CREDENTIAL_MAX_SIZE                   (256)
#endif

#if !defined(EDHOC_CREDENTIAL_ID_MAX_SIZE)
#define EDHOC_CREDENTIAL_ID_MAX_SIZE                (256)
#endif

#if !defined(EDHOC_ADD_DATA_MAX_SIZE)
#define EDHOC_ADD_DATA_MAX_SIZE                     (64)
#endif

#if (defined(EDHOC_CIPHER_SUITE_0_ENABLED) || \
     defined(EDHOC_CIPHER_SUITE_2_ENABLED)) && \
    (!defined(EDHOC_CIPHER_SUITE_1_ENABLED) && \
     !defined(EDHOC_CIPHER_SUITE_3_ENABLED))
#define EDHOC_AUTH_TAG_MAX_SIZE                     (8)
#else
#define EDHOC_AUTH_TAG_MAX_SIZE                     (16)
#endif

#define EDHOC_ECC_KEY_MAX_SIZE                      (32)
#define EDHOC_SHARED_SECRET_MAX_SIZE                (EDHOC_ECC_KEY_MAX_SIZE)
#define EDHOC_HASH_MAX_SIZE                         (32)
#define EDHOC_K23M_MAX_SIZE                         (16)
#define EDHOC_IV23M_MAX_SIZE                        (13)
#define EDHOC_SIG23_MAX_SIZE                        (64)

// CBOR format sizes
#define CBOR_ARRAY_LE23_FMT_SIZE                    (1)
#define CBOR_STR_LE23_FMT_SIZE                      (1)
#define CBOR_STR_LE256_FMT_SIZE                     (2)
#define CBOR_INT_LE256_FMT_SIZE                     (2)
#define CBOR_BYTES_LE23_FMT_SIZE                    (1)
#define CBOR_BYTES_LE256_FMT_SIZE                   (2)
#define CBOR_BYTES_LE65536_FMT_SIZE                 (3)


#if (EDHOC_CREDENTIAL_ID_MAX_SIZE <= 23)
#define CBOR_CREDENTIAL_ID_FMT_SIZE                 (CBOR_BYTES_LE23_FMT_SIZE)
#elif (EDHOC_CREDENTIAL_ID_MAX_SIZE > 23 && EDHOC_CREDENTIAL_ID_MAX_SIZE < 256)
#define CBOR_CREDENTIAL_ID_FMT_SIZE                 (CBOR_BYTES_LE256_FMT_SIZE)
#elif (EDHOC_CREDENTIAL_ID_MAX_SIZE >= 256 && EDHOC_CREDENTIAL_ID_MAX_SIZE < 65536)
#define CBOR_CREDENTIAL_ID_FMT_SIZE                 (CBOR_BYTES_LE65536_FMT_SIZE)
#else
#define CBOR_CREDENTIAL_ID_FMT_SIZE                 (9)
#endif

#if (EDHOC_CREDENTIAL_MAX_SIZE <= 23)
#define CBOR_CREDENTIAL_FMT_SIZE                    (CBOR_BYTES_LE23_FMT_SIZE)
#elif (EDHOC_CREDENTIAL_MAX_SIZE > 23 && EDHOC_CREDENTIAL_MAX_SIZE < 256)
#define CBOR_CREDENTIAL_FMT_SIZE                    (CBOR_BYTES_LE256_FMT_SIZE)
#elif (EDHOC_CREDENTIAL_MAX_SIZE >= 256 && EDHOC_CREDENTIAL_MAX_SIZE < 65536)
#define CBOR_CREDENTIAL_FMT_SIZE                    (CBOR_BYTES_LE65536_FMT_SIZE)
#else
#define CBOR_CREDENTIAL_FMT_SIZE                    (9)
#endif

#if (EDHOC_ADD_DATA_MAX_SIZE <= 23)
#define CBOR_ADD_DATA_FMT_SIZE                      (CBOR_BYTES_LE23_FMT_SIZE)
#elif (EDHOC_ADD_DATA_MAX_SIZE > 23 && EDHOC_ADD_DATA_MAX_SIZE < 256)
#define CBOR_ADD_DATA_FMT_SIZE                      (CBOR_BYTES_LE256_FMT_SIZE)
#elif (EDHOC_ADD_DATA_MAX_SIZE >= 256 && EDHOC_ADD_DATA_MAX_SIZE < 65536)
#define CBOR_ADD_DATA_FMT_SIZE                      (CBOR_BYTES_LE65536_FMT_SIZE)
#else
#define CBOR_ADD_DATA_FMT_SIZE                      (9)
#endif

#define EDHOC_AEAD_ID                                (1)

#define EDHOC_KDF_LABEL_MAX_SIZE                    (64)
#define EDHOC_KDF_INFO_MAX_SIZE                     (CBOR_ARRAY_LE23_FMT_SIZE +                                     \
                                                     CBOR_INT_LE256_FMT_SIZE + EDHOC_AEAD_ID +                      \
                                                     CBOR_BYTES_LE256_FMT_SIZE + EDHOC_HASH_MAX_SIZE +              \
                                                     CBOR_STR_LE256_FMT_SIZE + EDHOC_KDF_LABEL_MAX_SIZE +           \
                                                     CBOR_INT_LE256_FMT_SIZE + EDHOC_AEAD_ID)

#define EDHOC_PAYLOAD_MAX_SIZE                      (CBOR_CREDENTIAL_ID_FMT_SIZE + EDHOC_CREDENTIAL_ID_MAX_SIZE +   \
                                                     CBOR_BYTES_LE256_FMT_SIZE + EDHOC_SIG23_MAX_SIZE +             \
                                                     CBOR_ADD_DATA_FMT_SIZE + EDHOC_ADD_DATA_MAX_SIZE)


/**
 * @brief EDHOC error codes
 */
#define EDHOC_SUCCESS                               (0)

// crypto errors
#define EDHOC_ERR_CRYPTO                            (-2)
#define EDHOC_ERR_KEYGEN                            (-3)

// generic errors
#define EDHOC_ERR_INVALID_SIZE                      (-4)
#define EDHOC_ERR_BUFFER_OVERFLOW                   (-5)
#define EDHOC_ERR_INVALID_PARAM                     (-6)
#define EDHOC_ERR_ILLEGAL_STATE                     (-7)

// edhoc protocol config errors
#define EDHOC_ERR_INVALID_ROLE                      (-8)
#define EDHOC_ERR_INVALID_CORR                      (-9)

// edhoc cipher suite errors
#define EDHOC_ERR_CIPHERSUITE_UNAVAILABLE           (-10)
#define EDHOC_ERR_AEAD_CIPHER_UNAVAILABLE           (-11)
#define EDHOC_ERR_CURVE_UNAVAILABLE                 (-12)

// edhoc credential and key errors
#define EDHOC_ERR_INVALID_CRED                      (-13)
#define EDHOC_ERR_INVALID_CRED_ID                   (-14)
#define EDHOC_ERR_INVALID_CBOR_KEY                  (-15)

// cbor encoding/decoding errors
#define EDHOC_ERR_CBOR_ENCODING                     (-16)
#define EDHOC_ERR_CBOR_DECODING                     (-17)

/**
 * Macros to check return codes
 */
#define EDHOC_CHECK_SUCCESS(f)                                  \
do{                                                             \
    if((ret = (f)) != EDHOC_SUCCESS){                           \
        goto exit;                                              \
    }                                                           \
} while(0)

#define EDHOC_FAIL(x)                                           \
do{                                                             \
    ret = (x);                                                  \
    goto exit;                                                  \
} while(0)


/* Callback functions */
typedef int (*rng_cb_t)(void *, unsigned char *, size_t);

typedef int (*ad_cb_t)(unsigned char *, size_t, ssize_t *);

typedef void (*cred_cb_t)(void);

/* Defined below */
typedef struct edhoc_conf_t edhoc_conf_t;
typedef struct edhoc_session_t edhoc_session_t;
typedef struct edhoc_ctx_t edhoc_ctx_t;
typedef struct edhoc_cred_t edhoc_cred_t;
typedef struct cose_key_t cose_key_t;
typedef struct cred_container_t cred_container_t;
typedef struct cbor_cert_t cbor_cert_t;
typedef struct rpk_t rpk_t;

typedef void *cred_t;


/**
 * @brief COSE key types
 */
typedef enum cose_kty {
    COSE_KTY_NONE = 0,         /**< Invalid COSE key */
    COSE_KTY_OCTET = 1,        /**< Octet key pair (eddsa) */
    COSE_KTY_EC2 = 2,          /**< Elliptic curve */
} cose_kty_t;

/**
 * @brief COSE curve numbers
 */
typedef enum {
    COSE_EC_NONE = 0,                /**< Not an EC key */
    COSE_EC_CURVE_P256 = 1,          /**< secp256r1 */
    COSE_EC_CURVE_X25519 = 4,        /**< X25519, ECDH only */
    COSE_EC_CURVE_ED25519 = 6,       /**< Ed25519 for EdDSA only */
} cose_curve_t;

/**
 * @brief COSE algorithm numbers
 */
typedef enum {
    COSE_ALGO_NONE = 0,                     /**< Invalid algo */
    COSE_ALGO_SHA256 = -16,                 /**< SHA-256 */
    COSE_ALGO_EDDSA = -8,                   /**< EdDSA */
    COSE_ALGO_ES256 = -7,                   /**< ECDSA w/ SHA256 */
    COSE_ALGO_AESCCM_16_64_128 = 10,        /**< AES-CCM */
    COSE_ALGO_AESCCM_16_128_128 = 30,       /**< AES-CCM */
} cose_algo_t;

/**
 * @brief EDHOC cipher suites
 */
typedef enum {
    EDHOC_CIPHER_SUITE_0 = 0,
    EDHOC_CIPHER_SUITE_1,
    EDHOC_CIPHER_SUITE_2,
    EDHOC_CIPHER_SUITE_3,
} cipher_suite_id_t;

/**
 * @brief EDHOC authentication methods (Initiator | Responder)
 */
typedef enum {
    EDHOC_AUTH_SIGN_SIGN = 0,
    EDHOC_AUTH_SIGN_STATIC,
    EDHOC_AUTH_STATIC_SIGN,
    EDHOC_AUTH_STATIC_STATIC,
} method_t;

/**
 * @brief EDHOC correlation values
 */
typedef enum {
    NO_CORR = 0,
    CORR_1_2,
    CORR_2_3,
    CORR_ALL,
    CORR_UNSET
} corr_t;

/**
 * @brief EDHOC roles
 */
typedef enum {
    EDHOC_IS_RESPONDER = 0,
    EDHOC_IS_INITIATOR
} edhoc_role_t;

/**
 * @brief EDHOC credential types
 */
typedef enum {
    CRED_TYPE_CBOR_CERT = 0,
    CRED_TYPE_X509_CERT,
    CRED_TYPE_RPK
} cred_type_t;

/**
 * @brief EDHOC credential types
 */
typedef enum {
    CRED_ID_TYPE_X5T = 0,
    CRED_ID_TYPE_X5U,
    CRED_ID_TYPE_KID,
} cred_id_type_t;

/**
 * @brief EDHOC internal FSM states
 */
typedef enum {
    EDHOC_WAITING = 0,
    EDHOC_SENT_MESSAGE_1,
    EDHOC_RECEIVED_MESSAGE_1,
    EDHOC_SENT_MESSAGE_2,
    EDHOC_RECEIVED_MESSAGE_2,
    EDHOC_SENT_MESSAGE_3,
    EDHOC_RECEIVED_MESSAGE_3,
    EDHOC_FINALIZED,
    EDHOC_FAILED
} edhoc_state_t;

/**
 * @brief COSE key structure
 */
struct cose_key_t {
    cose_kty_t kty;                     /**< Key type */
    cose_algo_t algo;                   /**< Key algorithm restriction with this key */
    cose_curve_t crv;                   /**< Curve, algo is derived from this for now */
    uint8_t x[EDHOC_ECC_KEY_MAX_SIZE];  /**< X coordinate of the public key */
    size_t x_len;                       /**< Length of the X coordinate of the public key */

#if defined(EDHOC_CIPHER_SUITE_2_ENABLED) || defined(EDHOC_CIPHER_SUITE_3_ENABLED)
    uint8_t y[EDHOC_ECC_KEY_MAX_SIZE];  /**< Y coordinate of the public key, meaningless in case ok COSE_KTY_OCTET */
    size_t y_len;                       /**< Length of the Y coordinate of the public key */
#endif

    uint8_t d[EDHOC_ECC_KEY_MAX_SIZE];  /**< Private or secret key */
    size_t d_len;                       /**< Length of the private key */
};

struct cred_container_t {
    cose_key_t auth_key;
    cred_type_t cred_type;
    cred_t cred_pt;
    cred_id_type_t cred_id_type;
    const uint8_t *cred_id;
    size_t cred_id_len;
};

struct rpk_t {
    const char *subject_name;
    const uint8_t *buffer;
    size_t buflen;
};

struct cbor_cert_t {
    uint8_t *type;
    uint16_t *serial_number;
    const char *issuer;
    int *validity;
    const char *subject;
    const uint8_t *signature;
    const uint8_t *buffer;
    size_t buflen;
};

struct edhoc_conf_t {
    edhoc_role_t role;
    ad_cb_t ad1;
    ad_cb_t ad2;
    ad_cb_t ad3;
    cred_container_t local_cred;
    cred_cb_t f_remote_cred;
};

/**
 * @brief EDHOC Session struct. Holds the information and secrets that are used by the EDHOC exporter to derive
 * symmetric keys.
 */
struct edhoc_session_t {
    uint8_t cidi[EDHOC_CID_MAX_LEN];            ///< Connection identifier of the EDHOC Initiator.
    size_t cidi_len;                            ///< Length of the Initiator's connection identifier.
    uint8_t cidr[EDHOC_CID_MAX_LEN];            ///< Connection identifier of the EDHOC Responder.
    size_t cidr_len;                            ///< Length of the Responder's connection identifier.
    uint8_t cipher_suite;                       ///< Negotiated cipher suite.
    uint8_t prk_4x3m[EDHOC_HASH_MAX_SIZE];      ///< Secret master key derived during EDHOC handshake.
    uint8_t th_4[EDHOC_HASH_MAX_SIZE];          ///< Final transcript hash of the EDHOC handshake.
};

struct edhoc_ctx_t {
    edhoc_conf_t *conf;
    edhoc_state_t state;
    edhoc_session_t session;
    corr_t correlation;
    uint8_t method;
    cose_key_t local_eph_key;
    cose_key_t remote_eph_key;
    cose_key_t remote_auth_key;
    uint8_t secret[EDHOC_SHARED_SECRET_MAX_SIZE];
    uint8_t prk_2e[EDHOC_HASH_MAX_SIZE];
    uint8_t prk_3e2m[EDHOC_HASH_MAX_SIZE];
    uint8_t th_2[EDHOC_HASH_MAX_SIZE];
    uint8_t th_3[EDHOC_HASH_MAX_SIZE];
};

/**
 * @brief Initialize an EDHOC context object. Prepare it for edhoc_ctx_setup().
 *
 * @param[in,out] ctx       EDHOC context
 *
 */
void edhoc_ctx_init(edhoc_ctx_t *ctx);

/**
 * @brief Initialize the EDHOC configuration
 *
 * @param[in,out] conf      EDHOC configuration struct
 */
void edhoc_conf_init(edhoc_conf_t *conf);

/**
 * @brief Set up the EDHOC configuration
 *
 * @param ctx[in,out]       EDHOC context
 * @param conf[in]          EDHOC configuration struct
 */
void edhoc_ctx_setup(edhoc_ctx_t *ctx, edhoc_conf_t *conf);

/**
 * @brief Load the credential information
 *
 * @param[out] conf             The EDHOC configuration struct to populate
 * @param[in] t                 Credential type (CRED_TYPE_CBOR_CERT or CRED_TYPE_PUBKEY)
 * @param[in] local_cred        Pointer to the credential structure
 * @param[in] remote_cred_cb    Callback function to fetch remote credential information (can be NULL)
 *
 * @returns On success returns EDHOC_SUCCESS
 * @returns On failure returns a negative value
 */
int edhoc_conf_load_credentials(edhoc_conf_t *conf, cred_type_t t, void *local_cred, cred_cb_t remote_cred_cb);

/**
 * @brief Set up the EDHOC configuration.
 *
 * @param[out] conf             The EDHOC configuration struct to populate
 * @param[in] role              An EDHOC role; either EDHOC_IS_INITIATOR or EDHOC_IS_RESPONDER
 * @param[in] ad1_cb            Callback to fetch additional data
 * @param[in] ad2_cb            Callback to fetch additional data
 * @param[in] ad3_cb            Callback to fetch additional data
 *
 * @returns On success returns EDHOC_SUCCESS
 * @returns On failure returns a negative value
 *
 */
int edhoc_conf_setup(edhoc_conf_t *conf, edhoc_role_t role, ad_cb_t ad1_cb, ad_cb_t ad2_cb, ad_cb_t ad3_cb);

/**
 * @brief Load the private COSE key for authenticating the exchange.
 * It must correspond to the credentials loaded with edhoc_conf_load_authkey() or edhoc_conf_load_cbor_cert()
 *
 * @param conf
 */
int edhoc_conf_load_authkey(edhoc_conf_t *conf, const uint8_t *auth_key, size_t auth_key_len);

#if defined(EDHOC_AUTH_CBOR_CERT_ENABLED)

/**
 * @brief Load a CBOR certificate as credential for authentication
 *
 * @param[in,out] conf          The EDHOC configuration
 * @param[in] cbor_cert         Byte string containing the CBOR encoded certificate
 * @param[in] cbor_cert_len     Length of @p cbor_cert
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CBOR_DECODING
 */
int edhoc_cred_load_cbor_cert(cbor_cert_t *cert_ctx, const uint8_t *cbor_cert, size_t cbor_cert_len);

/**
 * @brief Initialize a CBOR certificate context for authentication
 *
 * @param[in] cert_ctx  CBOR certificate context
 *
 */
void edhoc_cred_cbor_cert_init(cbor_cert_t *cert_ctx);

#endif

#if defined(EDHOC_AUTH_RAW_PUBKEY_ENABLED)

/**
 * @brief Load a public COSE key as credential for authentication
 *
 * @param conf
 */
int edhoc_cred_load_pub_key(rpk_t *ctx, const uint8_t *pub_key, size_t pub_key_len);

/**
 * @brief Initialize a COSE key context for authentication
 *
 * @param[in] pub_key  COSE key context
 *
 */
void edhoc_cred_pub_key_init(rpk_t *key);

#endif

/**
 * @brief Load the credential identifier information
 *
 * @param conf
 * @param cred_id
 * @param cred_id_type
 * @param cred_id_len
 * @return
 */
int edhoc_conf_load_cred_id(edhoc_conf_t *conf,
                            const uint8_t *cred_id,
                            cred_id_type_t cred_id_type,
                            size_t cred_id_len);

/**
 * @brief EDHOC exporter interface to derive symmetric encryption keys and randomness from the shared master secret.
 *
 * @param[in] ctx       EDHOC context
 * @param[in] label     String label
 * @param[in] length    Length of the extract data
 * @param[out] out      Buffer to store the extracted data
 * @param[in] olen      Maximum capacity of @p out
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int edhoc_exporter(edhoc_ctx_t *ctx, const char *label, size_t length, uint8_t *out, size_t olen);

#if defined(EDHOC_DEBUG_ENABLED)

/**
 * @brief Load an ephemeral COSE key pair.
 *
 * @param conf
 */
int edhoc_load_ephkey(edhoc_ctx_t *ctx, const uint8_t *eph_key, size_t eph_key_len);

/**
 * @brief Load an ephemeral COSE key pair.
 *
 * @param conf
 */
int edhoc_session_preset_cidi(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len);

/**
 * @brief Load an ephemeral COSE key pair.
 *
 * @param conf
 */
int edhoc_session_preset_cidr(edhoc_ctx_t *ctx, const uint8_t *conn_id, size_t conn_id_len);

#endif

#if defined(EDHOC_ASYNC_API_ENABLED)

/**
 * @brief   Create EDHOC message 1
 *
 * @param[in] ctx               EDHOC context
 * @param[in] correlation       EDHOC correlation value
 * @param[in] m                 EHDOC authentication method
 * @param[in] id                Preferred cipher suite
 * @param[out] out              Output buffer to hold EDHOC message 1
 * @param[in] olen              Length of @p out
 *
 * @returns     On success the size of EDHOC message_1
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg1(edhoc_ctx_t *ctx,
                          corr_t correlation,
                          method_t m,
                          cipher_suite_id_t id,
                          uint8_t *out,
                          size_t olen);

/**
 * @brief   Create EDHOC message 2
 *
 * @param[in] ctx           EDHOC context
 * @param[in] msg1_buf      Buffer containing EDHOC message 1
 * @param[in] msg1_len      Length of EDHOC message 1
 * @param[in] ad2           Callback to fetch additional data (can be NULL)
 * @param[out] out          Output buffer to hold EDHOC message 1
 * @param[in] olen          Length of @p out
 *
 * @returns     On success size of EDHOC message 2
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx, const uint8_t *msg1_buf, size_t msg1_len, uint8_t *out, size_t olen);

/**
 * @brief   Create EDHOC message 3
 *
 * @param[in] ctx           EDHOC context
 * @param[in] msg2_buf      Buffer containing EDHOC message 2
 * @param[in] msg2_len      Length of @p msg2_buf
 * @param[in] ad2           Callback to fetch additional data (can be NULL)
 * @param[out] out          Output buffer to hold EDHOC message 3
 * @param[in] olen          Capacity of @p out
 *
 * @return  On success the size of EDHOC message 3
 * @return  On failure a negative value
 */
ssize_t edhoc_create_msg3(edhoc_ctx_t *ctx, const uint8_t *msg2_buf, size_t msg2_len, uint8_t *out, size_t olen);

/**
 * @brief   Finalize the EDHOC ecxhange on the Initiator side
 *
 * @param[in,out] ctx       EDHOC context
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
int edhoc_init_finalize(edhoc_ctx_t *ctx);

/**
 * @brief   Finalize the EDHOC ecxhange on the Responder side
 *
 * @param[in,out] ctx       EDHOC context
 * @param[in] msg3_buf      Buffer containing EDHOC message 3
 * @param[in] msg3_len      Length of @p msg3_buf
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
int edhoc_resp_finalize(edhoc_ctx_t *ctx, const uint8_t *msg3_buf, size_t msg3_len);

#else

/**
 * @brief   Perform the EDHOC handshake.
 *
 * @param[in] ctx           EDHOC context
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
int edhoc_do_handshake(edhoc_ctx_t *ctx);

#endif /* EDHOC_ASYNC_API_ENABLED */

#endif /* EDHOC_EDHOC_H */
