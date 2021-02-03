#ifndef EDHOC_CRYPTO_INTERNAL_H
#define EDHOC_CRYPTO_INTERNAL_H


#if defined(WOLFSSL)
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#elif defined(MBEDTLS)
#include <mbedtls/sha256.h>
#elif defined(HACL)
#else
#error "No crypto backend selected"
#endif

#include "edhoc/edhoc.h"

#if defined(HACL)
#define HASH_INPUT_BLEN         (1000)
#endif

typedef struct hash_ctx hash_ctx_t;

struct hash_ctx{
#if defined(WOLFSSL)
    wc_Sha256 digest_ctx;
#elif defined(MBEDTLS)
    mbedtls_sha256_context digest_ctx;
#elif defined(HACL)
    size_t fill_level;
    uint8_t input_buffer[HASH_INPUT_BLEN];
#else
#error "No crypto backend selected"
#endif
};

/**
 * @brief Generate a random key pair over a COSE curve
 *
 * @param[in] crv       COSE Curve over which the key will be generated
 * @param[in] f_rng     A function providing strong randomness
 * @param[in] p_rng     Optional RNG context info (can be NULL)
 * @param[in] key       Pointer to COSE key structure to store the generated key
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns a negative value (EDHOC_ERR_KEY_GENERATION, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_gen_keypair(cose_curve_t crv, rng_cb_t f_rng, void *p_rng, cose_key_t *key);

/**
 * @brief Initialize and start a hashing context
 *
 * @param[in] ctx   Hashing context
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_hash_init(hash_ctx_t* ctx);

/**
 * @brief Update the hashing context with
 *
 * @param[in] ctx   Hashing context
 * @param[in] in    Input buffer
 * @param[in] ilen  Length of @p in
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_hash_update(hash_ctx_t* ctx, const uint8_t *in, size_t ilen);

/**
 * @brief Finalize a hashing context
 *
 * @param[in] ctx    Hashing context
 * @param[out] out   Output buffer to store digest
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_hash_finish(hash_ctx_t* ctx, uint8_t *out);

/**
 * @brief Free the hashing context
 *
 * @param[in] digest_ctx    Hashing context
 *
 */
void crypt_hash_free(hash_ctx_t* ctx);

/**
 * @brief Compute the EDHOC-KDF
 *
 * @param[in] id        COSE algorithm identifier
 * @param[in] prk       Pseudo-random key (of lenght COSE_DIGEST_LEN)
 * @param[in] th        transcript hash
 * @param[in] label     String label
 * @param[in] length    KDF output length
 * @param[out] out      Output buffer
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO, EDHOC_ERR_CBOR_ENCODING or another negative value
 */
int
crypt_edhoc_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, int length, uint8_t *out);

/**
 * @brief Compute the EDHOC PRK_2e value.
 *
 * @param[in] shared_secret         The shared secret, computed with ECDH
 * @param[in] salt                  Salt for the hashing algorithm
 * @param[in] salt_len              Length of @p salt
 * @param[out] prk_2e               Output buffer, must be at least COSE_DIGEST_LEN in size
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 **/
int crypt_compute_prk2e(const uint8_t *shared_secret, const uint8_t *salt, size_t salt_len, uint8_t *prk_2e);

/**
 * @brief Compute the EDHOC PRK_3e2m value.

 * @param[in] role                  EDHOC role
 * @param[in] method                EDHOC authentication method
 * @param[in] prk_2e                EDHOC prk_2e value
 * @param[in] shared_secret         EDHOC ECDH shared secret
 * @param[out] prk_3e2m             EDHOC prk_3e2m computed value
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_compute_prk3e2m(edhoc_role_t role,
                          uint8_t method,
                          const uint8_t *prk_2e,
                          const uint8_t *shared_secret,
                          uint8_t *prk_3e2m);

/**
 * @brief Compute the EDHOC PRK_4x3m value.
 *
 * @param[in] role              EDHOC role
 * @param[in] method            EDHOC authentication method
 * @param[in] shared_secret     EDHOC ECDH shared secret
 * @param[in] prk_3e2m          EDHOC PRK_3e2m value
 * @param[out] prk_4x3m         EDHOC prk_4x3m computed value
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_compute_prk4x3m(edhoc_role_t role,
                          uint8_t method,
                          const uint8_t *shared_secret,
                          const uint8_t *prk_3e2m,
                          uint8_t *prk_4x3m);

/**
 * @brief Compute the ECDH secret.
 *
 * @param[in] crv           The curve over which the ECDH secret is computed
 * @param[in] private_key   COSE key where the private part must be set
 * @param[in] public_key    COSE key where the public part must be set
 * @param[in] f_rng         Function pointer to an RNG
 * @param[in] p_rng         Context for the RNG
 * @param[out] out          Output buffer, must be at least 32 bytes long
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns a negative value (i.e., EDHOC_ERR_CRYPTO, ...)
 */
int crypt_compute_ecdh(
        cose_curve_t crv,
        cose_key_t *private_key,
        cose_key_t *public_key,
        rng_cb_t f_rng,
        void *p_rng,
        uint8_t* out);

/**
 * @brief Encrypts and authenticates the payload using a COSE AEAD cipher
 *
 * @param[in] alg           COSE algorithm to use
 * @param[in] key           Authentication key
 * @param[in] iv            IV for the AEAD cipher
 * @param[in] aad           Additional data
 * @param[in] aad_len       Length of @p aad_len
 * @param[in] plaintext     Plaintext input
 * @param[out] ciphertext   Ciphertext
 * @param[in] ct_pl_len     Length of @p plaintext and @p ciphertext
 * @param[out] tag          Authentication tag
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_CRYPTO or another negative value
 */
int crypt_encrypt_aead(
        cose_algo_t alg,
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *aad,
        size_t aad_len,
        uint8_t *plaintext,
        uint8_t *ciphertext,
        size_t ct_pl_len,
        uint8_t *tag);


/**
 * @brief Decrypts and verifies the authenticity of a ciphertext using a COSE AEAD cipher
 *
 * @param[in] alg           COSE algorithm to use
 * @param[in] key           Authentication key
 * @param[in] iv            IV for the AEAD cipher
 * @param[in] aad           Additional data
 * @param[in] aad_len       Length of @p aad_len
 * @param[in] plaintext     Plaintext input
 * @param[out] ciphertext   Ciphertext
 * @param[in] ct_pl_len     Length of @p plaintext and @p ciphertext
 * @param[out] tag          Authentication tag
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_CRYPTO or another negative value
 */
int crypt_decrypt_aead(
        cose_algo_t alg,
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *aad,
        size_t aad_len,
        uint8_t *plaintext,
        uint8_t *ciphertext,
        size_t ct_pl_len,
        uint8_t *tag);

/**
 * @brief Compute a signature of the digest
 *
 * @param[in] crv           COSE curve for the signature calculation
 * @param[in] authkey       Private key
 * @param[in] msg        Message digest
 * @param[in] msg_len    Length of @p digest
 * @param[in] f_rng         Function providing randomness
 * @param[in] p_rng         Optional randomness context structure
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, a negative value (EDHOC_ERR_CRYPTO, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_compute_signature(cose_curve_t crv,
                            cose_key_t *authkey,
                            const uint8_t *msg,
                            size_t msg_len,
                            rng_cb_t f_rng,
                            void *p_rng,
                            uint8_t *signature);

#endif /* EDHOC_CRYPTO_INTERNAL_H */
