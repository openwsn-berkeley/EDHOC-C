#ifndef EDHOC_CRYPTO_INTERNAL_H
#define EDHOC_CRYPTO_INTERNAL_H


#include "edhoc/edhoc.h"

/**
 * @brief Generate a random key pair over a COSE curve
 *
 * @param[in] crv                   COSE Curve over which the key will be generated
 * @param f_rng[in]                 A function providing strong randomness
 * @param p_rng[in]                 Optional RNG context info (can be NULL)
 * @param key[out]                  Pointer to COSE key structure to store the generated key
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, a negative value (EDHOC_ERR_KEY_GENERATION, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_gen_keypair(cose_curve_t crv, rng_cb_t f_rng, void *p_rng, cose_key_t *key);

/**
 * @brief Initialize and start a hashing context
 *
 * @param digest_ctx[in]    Hashing context
 *
 * @return On success EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_CRYPTO
 */
int crypt_hash_init(void *digest_ctx);

/**
 * @brief Update the hashing context with
 *
 * @param digest_ctx[in]    Hashing context
 * @param in[in]            Input buffer
 * @param ilen[in]          Length of @p in
 *
 * @return On success EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_CRYPTO
 */
int crypt_hash_update(void *digest_ctx, const uint8_t *in, size_t ilen);

/**
 * @brief Finalize a hashing context
 *
 * @param digest_ctx[in]        Hashing context
 * @param output[out]           Output buffer to store digest, must be at least of size COSE_DIGEST_LEN
 *
 * @return On success EDHOC_SUCCESS
 * @return On failure EDHOC_ERR_CRYPTO
 */
int crypt_hash_finish(void *digest_ctx, uint8_t *output);

/**
 * @brief Free the hashing context
 *
 * @param digest_ctx[in]        Hashing context
 */
void crypt_hash_free(void *digest_ctx);

/**
 * @brief Compute the EDHOC-KDF
 *
 * @param id[in]        COSE algorithm identifier
 * @param prk[in]       Pseudo-random key (of lenght COSE_DIGEST_LEN)
 * @param th[in]        transcript hash
 * @param label[in]     String label
 * @param out[out]      Output buffer
 * @param olen[in]      KDF output length
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO, EDHOC_ERR_CBOR_ENCODING or another negative value
 */
int
crypt_edhoc_kdf(cose_algo_t id, const uint8_t *prk, const uint8_t *th, const char *label, uint8_t *out, size_t olen);

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
                          method_t method,
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
                          method_t method,
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
