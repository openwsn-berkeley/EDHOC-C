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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "cose.h"
#include "cbor_cert.h"

#if !defined(EDHOC_MAX_CID_LEN)
#define EDHOC_MAX_CID_LEN                (4)
#endif

#if !defined(EDHOX_MAX_SUPPORTED_SUITES)
#define EDHOC_MAX_SUPPORTED_SUITES       (5)
#endif

#if !defined(EDHOC_MAX_CRED_SIZE)
#define EDHOC_MAX_CRED_SIZE              (200)
#endif

#if !defined(EDHOC_MAX_CRED_ID_SIZE)
#define EDHOC_MAX_CRED_ID_SIZE           (50)
#endif

#define EDHOC_MAX_P2E_LEN                (80)
#define EDHOC_MAX_K2E_LEN                (80)
#define EDHOC_MAX_M2_OR_A2M_LEN          (200)
#define EDHOC_MAX_K2M_LEN                (16)
#define EDHOC_MAX_IV2M_LEN               (16)
#define EDHOC_MAX_MAC_OR_SIG2_LEN        (64)
#define EDHOC_MAX_KDFINFO_LEN            (50)

/*
 * EDHOC error codes
 */
#define EDHOC_SUCCESS                   (0)
#define EDHOC_ERR_RNG                   (-1)
#define EDHOC_ERR_ILLEGAL_CIPHERSUITE   (-2)
#define EDHOC_ERR_CURVE_UNAVAILABLE     (-3)
#define EDHOC_ERR_KEY_GENERATION        (-4)
#define EDHOC_ERR_INVALID_KEY           (-5)
#define EDHOC_ILLEGAL_CONN_ID           (-6)
#define EDHOC_ERR_ADDITIONAL_DATA       (-7)
#define EDHOC_ERR_DECODE_MESSAGE1       (-8)
#define EDHOC_ERR_DECODE_MESSAGE2       (-9)
#define EDHOC_ERR_DECODE_MESSAGE3       (-10)
#define EDHOC_ERR_BUFFER_OVERFLOW       (-11)
#define EDHOC_ERR_CBOR_ENCODING         (-12)
#define EDHOC_ERR_ILLEGAL_ROLE          (-13)
#define EDHOC_ERR_ILLEGAL_CORR          (-14)
#define EDHOC_ERR_ILLEGAL_METHOD        (-15)
#define EDHOC_ERR_CRYPTO                (-16)
#define EDHOC_ERR_CBOR_DECODING         (-17)

#define EDHOC_CHECK_RET(f)                                      \
do{                                                             \
    if((ret = (f)) != EDHOC_SUCCESS){                           \
        goto exit;                                              \
    }                                                           \
} while(0)


/* Callback functions */
typedef int (*rng_cb_t)(void *, unsigned char *, size_t);

typedef void (*edhoc_cred_cb_t)(void);

/* Definitions for clarity */
typedef uint8_t cipher_suite_t;
typedef uint8_t method_t;

/* Defined in cbor certs */
typedef struct cbor_cert cbor_cert_t;

/* Defined below */
typedef struct edhoc_conf edhoc_conf_t;
typedef struct edhoc_session edhoc_session_t;
typedef struct edhoc_ctx edhoc_ctx_t;

typedef enum edhoc_corr {
    NO_CORR = 0,
    CORR_1_2,
    CORR_2_3,
    CORR_ALL,
    CORR_UNSET
} corr_t;

typedef enum edhoc_role {
    EDHOC_IS_RESPONDER = 0,
    EDHOC_IS_INITIATOR
} edhoc_role_t;

struct edhoc_conf {
    edhoc_role_t role;
    cose_key_t auth_key;
#if defined(EDHOC_AUTH_PUB_KEY)
    cose_key_t pub_key;
#endif
#if defined(EDHOC_AUTH_CBOR_CERT)
    cbor_cert_t certificate;
#endif
    edhoc_cred_cb_t edhoc_get_creds;
    const uint8_t *cred_id;
    size_t cred_id_len;
    rng_cb_t f_rng;
    void *p_rng;
};

struct edhoc_session {
    uint8_t cidi[EDHOC_MAX_CID_LEN];
    uint8_t cidi_len;
    uint8_t cidr[EDHOC_MAX_CID_LEN];
    uint8_t cidr_len;
    cipher_suite_t *selected_suite;
};

struct edhoc_ctx {
    edhoc_conf_t *conf;
    edhoc_session_t session;
    corr_t correlation;
    method_t *method;
    cose_key_t local_eph_key;
    cose_key_t remote_eph_key;
    uint8_t secret[COSE_MAX_KEY_LEN];
    uint8_t prk_2e[COSE_DIGEST_LEN];
    uint8_t prk_3e2m[COSE_DIGEST_LEN];
    uint8_t transcript_2[COSE_DIGEST_LEN];
    uint8_t transcript_3[COSE_DIGEST_LEN];
    uint8_t transcript_4[COSE_DIGEST_LEN];
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
 * @brief Set up the EDHOC configuration.
 *
 * @param conf[in,out]      The EDHOC configuration struct to populate
 * @param role[in]          An EDHOC role; either EDHOC_IS_INITIATOR or EDHOC_IS_RESPONDER
 * @param f_rng[in]         A function that provides strong random bytes
 * @param p_rng[in]         Optional RNG context object
 * @param cb[in]            Callback to fetch remote credential information
 *
 * @returns 0 on success
 * @returns A negative value on failure
 *
 */
int edhoc_conf_setup(edhoc_conf_t *conf, edhoc_role_t role, rng_cb_t f_rng, void *p_rng, edhoc_cred_cb_t cb);

/**
 * @brief Load the private COSE key for authenticating the exchange.
 * It must correspond to the credentials loaded with edhoc_conf_load_authkey() or edhoc_conf_load_cbor_cert()
 *
 * @param conf
 */
int edhoc_conf_load_authkey(edhoc_conf_t *conf, const uint8_t *auth_key, size_t auth_key_len);

#if defined(EDHOC_AUTH_CBOR_CERT)

/**
 * @brief Load a CBOR certificate as credential for authentication
 *
 * @param conf
 */
int edhoc_conf_load_cborcert(edhoc_conf_t *conf, const uint8_t *cbor_cert, size_t cbor_cert_len);

#endif

#if defined(EDHOC_AUTH_PUB_KEY)
/**
 * @brief Load a public COSE key as credential for authentication
 *
 * @param conf
 */
int edhoc_conf_load_pubkey(edhoc_conf_t *conf, const uint8_t *pub_key, size_t pub_key_len);
#endif

int edhoc_conf_load_cred_id(edhoc_conf_t *conf, const uint8_t *cred_id, size_t cred_id_len);

/**
 * @brief   Create EDHOC message 1
 *
 * @param ctx[in]           EDHOC context
 * @param correlation       EDHOC correlation value
 * @param method            EHDOC authentication method
 * @param suite             Preferred cipher suite
 * @param ad1[in]          Additional data
 * @param ad1_len[in]      Length of the addition
 * @param out[out]          Output buffer to hold EDHOC message 1
 * @param buf_len[in]       Length of @p out
 *
 * @returns     On success the size of EDHOC message_1
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg1(
        edhoc_ctx_t *ctx,
        corr_t correlation,
        method_t method,
        cipher_suite_t suite,
        const uint8_t *ad1,
        size_t ad1_len,
        uint8_t *out,
        size_t buf_len);

/**
 * @brief   Create EDHOC message 2
 *
 * @param ctx[in]           EDHOC context
 * @param msg1_buf[in]      Buffer containing EDHOC message 1
 * @param msg1_len[in]      Length of EDHOC message 1
 * @param aad2[in]          Additional data
 * @param aad2_len[in]      Length of the addition
 * @param out[out]          Output buffer to hold EDHOC message 1
 * @param olen[in]       Length of @p out
 *
 * @returns     On success size of EDHOC message_2
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg2(
        edhoc_ctx_t *ctx,
        const uint8_t *msg1_buf,
        size_t msg1_len,
        const uint8_t *aad1,
        size_t aad1_len,
        uint8_t *out,
        size_t olen);

#if defined(EDHOC_DEBUG_ENABLE)

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

#endif /* EDHOC_EDHOC_H */
