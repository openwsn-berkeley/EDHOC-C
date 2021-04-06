#ifndef EDHOC_EDHOC_H
#define EDHOC_EDHOC_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"
#include "edhoc/credentials.h"
#include "edhoc/cose.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

/**
 * @brief Definitions for internal buffer sizes
 */
#if !defined(EDHOC_CID_LEN)
#define EDHOC_CID_LEN                               (4)
#endif

#if !defined(EDHOC_CRED_SIZE)
#define EDHOC_CRED_SIZE                             (256)
#endif

#if !defined(EDHOC_CRED_ID_SIZE)
#define EDHOC_CRED_ID_SIZE                          (256)
#endif

#if !defined(EDHOC_ADDITIONAL_DATA_SIZE)
#define EDHOC_ADATA_SIZE                            (64)
#endif

// CBOR header size margin
#define CBOR_HDR                                    (3) // length-encoding up to 65535

#define EDHOC_DH_SECRET_SIZE                        (COSE_ECC_KEY_SIZE)
#define EDHOC_DIGEST_SIZE                           (32)
#define EDHOC_K23M_SIZE                             (16)
#define EDHOC_IV23M_SIZE                            (13)
#define EDHOC_MAC23_SIZE                            (16)
#define EDHOC_SIGNATURE23_SIZE                      (64)
#define EDHOC_EXTDATA_SIZE                          (3 * CBOR_HDR + EDHOC_DIGEST_SIZE \
                                                                  + EDHOC_CRED_SIZE   \
                                                                  + EDHOC_ADDITIONAL_DATA_SIZE)
#define EDHOC_ASSOCIATED_DATA_SIZE                  (3 * CBOR_HDR + strlen("Encrypt0") \
                                                                  + EDHOC_DIGEST_SIZE  \
                                                                  + EDHOC_EXTDATA_SIZE)
#define EDHOC_TOBESIGNED_SIZE                       (4 * CBOR_HDR + strlen("Signature1") \
                                                                  + EDHOC_CRED_ID_SIZE   \
                                                                  + EDHOC_EXTDATA_SIZE   \
                                                                  + EDHOC_MAC23_SIZE)
#define EDHOC_PLAINTEXT23_SIZE                       (3 * CBOR_HDR + EDHOC_CRED_ID_SIZE \
                                                                  + EDHOC_SIGNATURE23_SIZE \
                                                                  + EDHOC_ADDITIONAL_DATA_SIZE)
#define EDHOC_KEYSTREAM2_SIZE                       (EDHOC_PLAINTEXT23_SIZE)
#define EDHOC_MAX_LABEL_SIZE                        (64)

/**
 * @brief EDHOC error codes
 */
#define EDHOC_SUCCESS                               (0x00)

// crypto errors
#define EDHOC_ERR_CRYPTO                            (-0x01)
#define EDHOC_ERR_KEYGEN                            (-0x02)
#define EDHOC_ERR_RANDOMNESS                        (-0x03)

// generic errors
#define EDHOC_ERR_INVALID_SIZE                      (-0x04)
#define EDHOC_ERR_BUFFER_OVERFLOW                   (-0x05)
#define EDHOC_ERR_ILLEGAL_STATE                     (-0x06)

// edhoc protocol config errors
#define EDHOC_ERR_UNSUPPORTED_ROLE                  (-0x07)
#define EDHOC_ERR_UNSUPPORTED_CORR                  (-0x08)
#define EDHOC_ERR_UNSUPPORTED_METHOD                (-0x09)

// edhoc cipher suite errors
#define EDHOC_ERR_CIPHERSUITE_UNAVAILABLE           (-0x0a)
#define EDHOC_ERR_PRIOR_CIPHERSUITE_SUPPORTED       (-0x0b)
#define EDHOC_ERR_AEAD_CIPHER_UNAVAILABLE           (-0x0c)
#define EDHOC_ERR_SIGN_ALGORITHM_UNAVAILABLE        (-0x0d)
#define EDHOC_ERR_HASH_ALGORITHM_UNAVAILABLE        (-0x0e)
#define EDHOC_ERR_CURVE_UNAVAILABLE                 (-0x0f)

// edhoc credential and key errors
#define EDHOC_ERR_INVALID_CRED                      (-0x10)
#define EDHOC_ERR_INVALID_CRED_ID                   (-0x11)
#define EDHOC_ERR_INVALID_KEY                       (-0x12)

// cbor encoding/decoding errors
#define EDHOC_ERR_CBOR_ENCODING                     (-0x13)
#define EDHOC_ERR_CBOR_DECODING                     (-0x14)

// error during processing of EDHOC error message
#define ERR_EDHOC_ERROR_MESSAGE                     (-0x15)

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
typedef int (*ad_cb_t)(unsigned char *, size_t, ssize_t *);

typedef int (*edhoc_cred_cb_t)(const uint8_t *, size_t, const uint8_t **, size_t *);

/* Defined below */
typedef struct edhoc_conf_t edhoc_conf_t;
typedef struct edhoc_session_t edhoc_session_t;
typedef struct edhoc_ctx_t edhoc_ctx_t;
typedef struct edhoc_cred_container_t edhoc_cred_container_t;

/**
 * @brief EDHOC cipher suites
 */
typedef enum cipher_suite {
    EDHOC_CIPHER_SUITE_0 = 0,
    EDHOC_CIPHER_SUITE_1,
    EDHOC_CIPHER_SUITE_2,
    EDHOC_CIPHER_SUITE_3,
} cipher_suite_id_t;

/**
 * @brief EDHOC authentication methods (Initiator | Responder)
 */
typedef enum method {
    EDHOC_AUTH_SIGN_SIGN = 0,
    EDHOC_AUTH_SIGN_STATIC,
    EDHOC_AUTH_STATIC_SIGN,
    EDHOC_AUTH_STATIC_STATIC,
} method_t;

/**
 * @brief EDHOC correlation values
 */
typedef enum correlation {
    NO_CORR = 0,
    CORR_1_2,
    CORR_2_3,
    CORR_ALL,
    CORR_UNSET
} corr_t;

/**
 * @brief EDHOC roles
 */
typedef enum role {
    EDHOC_IS_RESPONDER = 0,
    EDHOC_IS_INITIATOR
} edhoc_role_t;


/**
 * @brief EDHOC internal FSM states
 */
typedef enum state {
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

typedef void *cred_t;

/**
 * @brief Container for the EDHOC credential information
 */
struct edhoc_cred_container_t {
    cose_key_t *authKey;              /**< Private authentication key */

    cred_type_t credType;             /**< credential type (RPK or CBOR certificate) */
    cred_t credCtx;                   /**< Pointer to a populated credential context */
    cred_id_t *idCtx;                 /**< Pointer to the raw credential identifier bytes */
};

struct edhoc_conf_t {
    edhoc_role_t role;
    ad_cb_t ad1;
    ad_cb_t ad2;
    ad_cb_t ad3;
    edhoc_cred_container_t myCred;
    edhoc_cred_cb_t f_remote_cred;
};

/**
 * @brief EDHOC Session struct. Holds the information and secrets that are used by the EDHOC exporter to derive
 * symmetric keys.
 */
struct edhoc_session_t {
    uint8_t cidi[EDHOC_CID_LEN];            ///< Connection identifier of the EDHOC Initiator.
    size_t cidiLen;                            ///< Length of the Initiator's connection identifier.
    uint8_t cidr[EDHOC_CID_LEN];            ///< Connection identifier of the EDHOC Responder.
    size_t cidrLen;                            ///< Length of the Responder's connection identifier.
    uint8_t cipherSuiteID;                       ///< Negotiated cipher suite.
    uint8_t prk4x3m[EDHOC_DIGEST_SIZE];      ///< Secret master key derived during EDHOC handshake.
    uint8_t th4[EDHOC_DIGEST_SIZE];          ///< Final transcript hash of the EDHOC handshake.
};

struct edhoc_ctx_t {
    edhoc_conf_t *conf;
    edhoc_state_t state;
    edhoc_session_t session;
    corr_t correlation;
    uint8_t method;
    void *thCtx;
    cose_key_t myEphKey;
    uint8_t secret[EDHOC_DH_SECRET_SIZE];
    uint8_t prk2e[EDHOC_DIGEST_SIZE];
    uint8_t prk3e2m[EDHOC_DIGEST_SIZE];
    uint8_t th2[EDHOC_DIGEST_SIZE];
    uint8_t th3[EDHOC_DIGEST_SIZE];
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
void edhoc_ctx_setup(edhoc_ctx_t *ctx, edhoc_conf_t *conf, void *thCtx);

/**
 *
 * @param conf
 * @param role
 * @return
 */
int edhoc_conf_setup_role(edhoc_conf_t *conf, edhoc_role_t role);

/**
 *
 * @param conf
 * @param authKey
 * @param credType
 * @param credCtx
 * @param idCtx
 * @param f_remote_cred
 * @return
 */
int edhoc_conf_setup_credentials(edhoc_conf_t *conf,
                                 cose_key_t *authKey,
                                 cred_type_t credType,
                                 cred_t credCtx,
                                 cred_id_t *idCtx,
                                 edhoc_cred_cb_t f_remote_cred);

/**
 *
 * @param conf
 * @param ad1Cb
 * @param ad2Cb
 * @param ad3Cb
 * @return
 */
void edhoc_conf_setup_ad_callbacks(edhoc_conf_t *conf, ad_cb_t ad1Cb, ad_cb_t ad2Cb, ad_cb_t ad3Cb);


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
 * @param[in] msg1Buf      Buffer containing EDHOC message 1
 * @param[in] msg1_len      Length of EDHOC message 1
 * @param[out] out          Output buffer to hold EDHOC message 1
 * @param[in] olen          Length of @p out
 *
 * @returns     On success size of EDHOC message 2
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx, const uint8_t *msg1Buf, size_t msg1_len, uint8_t *out, size_t olen);

/**
 * @brief   Create EDHOC message 3
 *
 * @param[in] ctx           EDHOC context
 * @param[in] msg2_buf      Buffer containing EDHOC message 2
 * @param[in] msg2_len      Length of @p msg2_buf
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
ssize_t edhoc_init_finalize(edhoc_ctx_t *ctx);

/**
 * @brief   Finalize the EDHOC ecxhange on the Responder side
 *
 * @param[in,out] ctx       EDHOC context
 * @param[in] in      Buffer containing EDHOC message 3
 * @param[in] ilen      Length of @p msg3_buf
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure a negative value
 */
ssize_t edhoc_resp_finalize(edhoc_ctx_t *ctx, const uint8_t *in, size_t ilen, bool msg4, uint8_t *out, size_t olen);

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

#if defined(EDHOC_DEBUG_ENABLED)

/**
 * @brief Load an ephemeral COSE key pair.
 *
 * @param conf
 */
int edhoc_load_ephkey(edhoc_ctx_t *ctx, const uint8_t *ephKey, size_t ephKeyLen);

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

#endif /* EDHOC_EDHOC_H */
