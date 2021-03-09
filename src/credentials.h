#ifndef EDHOC_CREDENTIALS_H
#define EDHOC_CREDENTIALS_H

/**
 * @brief Wrap a CBOR-encoded certificate into a cbor_cert_t structure.
 *
 * @param[in,out] ctx      A CBOR cert structure that will get populated.
 * @param[in] cert_buffer       A CBOR encoded certificate (native).
 * @param[in] buflen            The length of the CBOR certificate.
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CBOR_DECODING
 */
int cred_cert_load_from_cbor(cbor_cert_t *ctx, const uint8_t *cert_buffer, size_t buflen);

/**
 * @brief Wrap a CBOR-encoded raw public authentication key into a rpk_t structure.
 *
 * @param[in,out] ctx       A key structure that will get populated.
 * @param[in] rpk_buffer           A COSE key
 * @param[in] buflen            The length of the CBOR certificate.
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CBOR_DECODING
 */
int cred_rpk_load_from_cbor(rpk_t *ctx, const uint8_t *rpk_buffer, size_t buflen);

/**
 * @brief Getter for the raw CBOR-encoded authentication material.
 *
 * @param[in] local_cred    Pointer to the local credentials
 * @param[in] cred_type     Credential type, i.e., CRED_TYPE_CBOR_CERT or CRED_TYPE_RPK
 * @param[out] ptr          Pointer that will be set to the CBOR encoded authentication material.
 *
 * @return On success returns the size of the CBOR encoded authentication material.
 */
ssize_t cred_get_cred_bytes(const cred_container_t* cred, const uint8_t **ptr);

/**
 * @brief Getter for the credential identifier. T
 *
 * The getter abstracts the management of the different credential identifiers and returns the appropriate
 * part of the CRED_ID based on its type.
 *
 * @param[out] out  Output buffer which will hold the encoded credential identifier
 * @param[in] olen  Maximum capacity of @p out
 *
 * @return On success returns the size of the CBOR encoded authentication material.
 */
ssize_t cred_get_cred_id_bytes(const cred_container_t* cred, uint8_t *out, size_t olen);

#endif /* EDHOC_CREDENTIALS_H */
