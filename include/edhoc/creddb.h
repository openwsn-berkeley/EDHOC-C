#include "edhoc/edhoc.h"

extern const uint8_t x509_der_cert_init_tv1[];
extern const uint8_t x509_auth_key_init_tv1[];
extern const uint8_t x509_der_cert_init_id_tv1[];
extern const uint8_t x509_der_cert_resp_tv1[];
extern const uint8_t x509_der_cert_resp_id_tv1[];
extern const uint8_t x509_auth_key_resp_tv1[];

extern const uint8_t rpk_cbor_init_tv2[];
extern const uint8_t rpk_auth_key_init_tv2[];
extern const uint8_t rpk_cbor_init_id_tv2[];
extern const uint8_t rpk_cbor_resp_tv2[];
extern const uint8_t rpk_auth_key_resp_tv2[];
extern const uint8_t rpk_cbor_resp_id_tv2[];

extern const uint8_t x509_der_cert_init_tv3[];
extern const uint8_t x509_der_cert_init_id_tv3[];
extern const uint8_t x509_auth_key_init_tv3[];
extern const uint8_t rpk_cbor_resp_tv3[];
extern const uint8_t rpk_cbor_resp_id_tv3[];
extern const uint8_t rpk_auth_key_resp_tv3[];

extern const uint8_t rpk_cbor_init_tv4[];
extern const uint8_t rpk_cbor_init_id_tv4[];
extern const uint8_t rpk_auth_key_init_tv4[];
extern const uint8_t x509_der_cert_resp_tv4[];
extern const uint8_t x509_der_cert_resp_id_tv4[];
extern const uint8_t x509_auth_key_resp_tv4[];

int f_remote_creds(const uint8_t *key, size_t keyLen, cred_type_t *credType, const uint8_t **cred, size_t *credLen,
                   const uint8_t **authKey, size_t *authKeyLen);
