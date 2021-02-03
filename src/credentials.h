#ifndef EDHOC_CREDENTIALS_H
#define EDHOC_CREDENTIALS_H

/*
 * @brief Load a CBOR certificate into a cbor_cert_t structure.
 *
 * @param[in,out] cert_ctx      A CBOR cert structure that will get populated.
 * @param[in] certificate       A CBOR encoded certificate (native).
 * @param[in] length            The length of the CBOR certificate.
 *
 * @return On success returns EDHOC_SUCCESS
 * @return On failure returns EDHOC_ERR_CBOR_DECODING
 */
int cbor_cert_load_from_cbor(cbor_cert_t *cert_ctx, const uint8_t* certificate, size_t length);



#endif /* EDHOC_CREDENTIALS_H */
