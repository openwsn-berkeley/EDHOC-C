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

/**
 * Internal buffer sizes
 */
#define EDHOC_MAX_M23_OR_A23M_LEN        (500)
#define EDHOC_MAX_K23M_LEN               (16)
#define EDHOC_MAX_IV23M_LEN              (16)
#define EDHOC_MAX_MAC_OR_SIG23_LEN       (64)
#define EDHOC_MAX_A3AE_LEN               (45)
#define EDHOC_MAX_KDF_INFO_LEN           (50)
#define EDHOC_MAX_PAYLOAD_LEN            (400)
#define EDHOC_MAX_EXAD_DATA_LEN          (50)
#define EDHOC_MAX_AUTH_TAG_LEN           (16)


/**
 * EDHOC error codes
 */
#define EDHOC_SUCCESS                   (0)

#define EDHOC_ERR_RNG                   (-1)
#define EDHOC_ERR_CRYPTO                (-2)

#define EDHOC_ERR_INVALID_ROLE          (-3)
#define EDHOC_ERR_INVALID_AUTH_METHOD   (-4)
#define EDHOC_ERR_INVALID_CORR          (-5)
#define EDHOC_ERR_INVALID_CIPHERSUITE   (-6)
#define EDHOC_ERR_AEAD_UNAVAILABLE      (-7)
#define EDHOC_ERR_CURVE_UNAVAILABLE     (-8)
#define EDHOC_ERR_INVALID_CBOR_KEY      (-9)

#define EDHOC_ERR_KEY_GENERATION        (-10)

#define EDHOC_ERR_BUFFER_OVERFLOW       (-11)

#define EDHOC_ERR_CBOR_ENCODING         (-12)
#define EDHOC_ERR_CBOR_DECODING         (-13)


#define EDHOC_CHECK_RET(f)                                      \
do{                                                             \
    if((ret = (f)) != EDHOC_SUCCESS){                           \
        goto exit;                                              \
    }                                                           \
} while(0)


/* Callback functions */
typedef int (*rng_cb_t)(void *, unsigned char *, size_t);

typedef int (*ad_cb_t)(unsigned char *, size_t, ssize_t *);

typedef void (*cred_cb_t)(void);

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
    ad_cb_t ad1;
    ad_cb_t ad2;
    ad_cb_t ad3;
    cose_key_t auth_key;
#if defined(EDHOC_AUTH_PUB_KEY)
    cose_key_t pub_key;
#endif
#if defined(EDHOC_AUTH_CBOR_CERT)
    cbor_cert_t certificate;
#endif
    cred_cb_t get_edhoc_creds;
    const uint8_t *cred_id;
    size_t cred_id_len;
    rng_cb_t f_rng;
    void *p_rng;
};

struct edhoc_session {
    uint8_t cidi[EDHOC_MAX_CID_LEN];
    size_t cidi_len;
    uint8_t cidr[EDHOC_MAX_CID_LEN];
    size_t cidr_len;
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
    uint8_t prk_4x3m[COSE_DIGEST_LEN];
    uint8_t th_2[COSE_DIGEST_LEN];
    uint8_t th_3[COSE_DIGEST_LEN];
    uint8_t th_4[COSE_DIGEST_LEN];
    uint8_t ct_or_pld_2[EDHOC_MAX_PAYLOAD_LEN];
    size_t ct_or_pld_2_len;
    uint8_t ct_or_pld_3[EDHOC_MAX_PAYLOAD_LEN];
    size_t ct_or_pld_3_len;
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
 * @param[out] conf         The EDHOC configuration struct to populate
 * @param[in] role          An EDHOC role; either EDHOC_IS_INITIATOR or EDHOC_IS_RESPONDER
 * @param[in] f_rng         A function that provides strong random bytes
 * @param[in] p_rng         Optional RNG context object
 * @param[in] cred_cb       Callback to fetch remote credential information
 * @param[in] ad1_cb        Callback to fetch additional data
 * @param[in] ad2_cb        Callback to fetch additional data
 * @param[in] ad3_cb        Callback to fetch additional data
 *
 * @returns 0 on success
 * @returns A negative value on failure
 *
 */
int edhoc_conf_setup(edhoc_conf_t *conf,
                     edhoc_role_t role,
                     rng_cb_t f_rng,
                     void *p_rng,
                     cred_cb_t cred_cb,
                     ad_cb_t ad1_cb,
                     ad_cb_t ad2_cb,
                     ad_cb_t ad3_cb);

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
 * @param[in] ctx               EDHOC context
 * @param[in] correlation       EDHOC correlation value
 * @param[in] method            EHDOC authentication method
 * @param[in] suite             Preferred cipher suite
 * @param[out] out              Output buffer to hold EDHOC message 1
 * @param[in] buf_len           Length of @p out
 *
 * @returns     On success the size of EDHOC message_1
 * @returns     On failure a negative value
 */
ssize_t edhoc_create_msg1(
        edhoc_ctx_t *ctx,
        corr_t correlation,
        method_t method,
        cipher_suite_t suite,
        uint8_t *out,
        size_t buf_len);

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
ssize_t edhoc_create_msg2(
        edhoc_ctx_t *ctx,
        const uint8_t *msg1_buf,
        size_t msg1_len,
        uint8_t *out,
        size_t olen);

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
ssize_t edhoc_create_msg3(
        edhoc_ctx_t *ctx,
        const uint8_t *msg2_buf,
        size_t msg2_len,
        uint8_t *out,
        size_t olen);

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
