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
 * @param[in] secret        The shared secret, computed with ECDH
 * @param[in] salt          Salt for the hashing algorithm
 * @param[in] salt_len      Length of @p salt
 * @param[out] out          Output buffer, must be at least COSE_DIGEST_LEN in size
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 **/
int crypt_compute_prk2e(const uint8_t *secret, const uint8_t *salt, size_t salt_len, uint8_t *out);

/*
 * @brief Compute the EDHOC PRK_3e2m value.
 */
int crypt_compute_prk3e2m(
        edhoc_role_t role,
        method_t method,
        uint8_t *prk2e,
        uint8_t shared_secret[32],
        uint8_t *prk3e2m);

/**
 * @brief Compute the ECDH secret.
 *
 * @param crv
 * @param private_key
 * @param public_key
 * @param out_buf
 * @param f_rng
 * @param p_rng
 *
 * @return
 */
int crypt_compute_ecdh(
        cose_curve_t crv,
        cose_key_t *private_key,
        cose_key_t *public_key,
        uint8_t out_buf[COSE_MAX_KEY_LEN],
        rng_cb_t f_rng,
        void *p_rng);

/**
 *
 * @param alg
 * @param key
 * @param iv
 * @param aad
 * @param aad_len
 * @param tag
 * @return
 */
int crypt_aead_tag(
        cose_algo_t alg,
        const uint8_t *key,
        const uint8_t *iv,
        const uint8_t *aad,
        size_t aad_len,
        uint8_t *tag);

/**
 * @brief Compute a signature of the digest
 *
 * @param[in] crv           COSE curve for the signature calculation
 * @param[in] authkey       Private key
 * @param[in] digest        Message digest
 * @param[in] digest_len    Length of @p digest
 * @param[in] f_rng         Function providing randomness
 * @param[in] p_rng         Optional randomness context structure
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, a negative value (EDHOC_ERR_CRYPTO, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_compute_signature(cose_curve_t crv,
                            cose_key_t *authkey,
                            const uint8_t *digest,
                            size_t digest_len,
                            rng_cb_t f_rng,
                            void *p_rng);

#endif /* EDHOC_CRYPTO_INTERNAL_H */
