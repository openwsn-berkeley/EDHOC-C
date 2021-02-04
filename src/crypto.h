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

struct hash_ctx {
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
int crypt_hash_init(hash_ctx_t *ctx);

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
int crypt_hash_update(hash_ctx_t *ctx, const uint8_t *in, size_t ilen);

/**
 * @brief Finalize a hashing context
 *
 * @param[in] ctx    Hashing context
 * @param[out] out   Output buffer to store digest
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_hash_finish(hash_ctx_t *ctx, uint8_t *out);

/**
 * @brief Free the hashing context
 *
 * @param[in] digest_ctx    Hashing context
 *
 */
void crypt_hash_free(hash_ctx_t *ctx);

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
crypt_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, int length, uint8_t *out);

/**
 * @brief Compute the EDHOC PRK_2e value.
 *
 * @param[in] sk        Public key
 * @param[in] pk        Private key
 * @param[in] f_rng     RNG function, can be NULL
 * @param[in] p_rng     Context for @p f_rng, can be NULL
 * @param[out] prk_2e   Output buffer, must be at least COSE_DIGEST_LEN in size
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 **/
int crypt_derive_prk(const cose_key_t *sk,
                     const cose_key_t *pk,
                     const uint8_t *salt,
                     size_t salt_len,
                     rng_cb_t f_rng,
                     void *p_rng,
                     uint8_t *prk);

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
int crypt_encrypt(cose_algo_t alg,
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
int crypt_decrypt(cose_algo_t alg,
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
 * @param[in] authkey       Private key
 * @param[in] msg           Message to sign
 * @param[in] msg_len       Length of @p msg
 * @param[in] f_rng         Function providing randomness
 * @param[in] p_rng         Optional randomness context structure
 *
 * @return On success returns the size of the signature
 * @return On failure returns an EDHOC error code (< 0, i.e., EDHOC_ERR_CRYPTO, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_sign(cose_key_t *authkey,
               const uint8_t *msg,
               size_t msg_len,
               rng_cb_t f_rng,
               void *p_rng,
               uint8_t *signature);

#endif /* EDHOC_CRYPTO_INTERNAL_H */
