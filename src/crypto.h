#ifndef EDHOC_CRYPTO_INTERNAL_H
#define EDHOC_CRYPTO_INTERNAL_H


#if defined(WOLFSSL)

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#elif defined(HACL)

#define HASH_INPUT_BLEN     (256)

typedef struct hacl_Sha256 hacl_Sha256;

struct hacl_Sha256 {
    uint16_t fillLevel;
    uint8_t buffer[HASH_INPUT_BLEN];
};
#elif defined(EMPTY_X509)
#elif defined(TINYCRYPT)
#include "crypto/tinycrypt/sha256.h"
#else
#error "No crypto backend selected"
#endif

#include "edhoc/edhoc.h"


/**
 * @brief Generate a random key pair over a COSE curve
 *
 * @param[in] crv       COSE Curve over which the key will be generated
 * @param[in] key       Pointer to COSE key structure to store the generated key
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns a negative value (EDHOC_ERR_KEY_GENERATION, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_gen_keypair(cose_curve_t crv, cose_key_t *key);

/**
 * @brief Initialize and start a hashing context
 *
 * @param[in] ctx   Hashing context
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_hash_init(void *ctx);

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
int crypt_hash_update(void *ctx, const uint8_t *in, size_t ilen);

/**
 * @brief Finalize a hashing context
 *
 * @param[in] ctx    Hashing context
 * @param[out] out   Output buffer to store digest
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CRYPTO
 */
int crypt_hash_finish(void *ctx, uint8_t *out);

/**
 * @brief Free the hashing context
 *
 * @param[in] digest_ctx    Hashing context
 *
 */
void crypt_hash_free(void *ctx);

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
int crypt_kdf(const uint8_t *prk, const uint8_t *info, size_t infoLen, uint8_t *out, size_t olen);

/**
 * @brief Compute the EDHOC PRK_2e value.
 *
 * @param[in] sk        Public key
 * @param[in] pk        Private key
 * @param[out] prk_2e   Output buffer, must be at least COSE_DIGEST_LEN in size
 *
 * @return On success, EDHOC_SUCCESS
 * @return On failure, EDHOC_ERR_CRYPTO
 **/
int crypt_derive_prk(const cose_key_t *sk, const cose_key_t *pk, const uint8_t *salt, size_t saltLen, uint8_t *prk);

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
int crypt_encrypt(const cose_key_t *sk,
                  const uint8_t *iv,
                  size_t ivLen,
                  const uint8_t *aad,
                  size_t aadLen,
                  uint8_t *in,
                  uint8_t *out,
                  size_t inOutLen,
                  uint8_t *tag,
                  size_t tagLen);


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
int crypt_decrypt(const cose_key_t *sk,
                  const uint8_t *iv,
                  size_t ivLen,
                  const uint8_t *aad,
                  size_t aadLen,
                  uint8_t *in,
                  uint8_t *out,
                  size_t inOutLen,
                  uint8_t *tag,
                  size_t tagLen);

/**
 *
 * @param dstCtx
 * @param srcCtx
 * @return
 */
int crypt_copy_hash_context(void *dstCtx, void *srcCtx);

/**
 * @brief Compute a signature of the digest
 *
 * @param[in] authkey       Private key
 * @param[in] msg           Message to sign
 * @param[in] msgLen       Length of @p msg
 *
 * @return On success returns the size of the signature
 * @return On failure returns an EDHOC error code (< 0, i.e., EDHOC_ERR_CRYPTO, EDHOC_ERR_CURVE_UNAVAILABLE, ..)
 */
int crypt_sign(const cose_key_t *authkey, const uint8_t *msg, size_t msgLen, uint8_t *signature, size_t *sigLen);

#endif /* EDHOC_CRYPTO_INTERNAL_H */
