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

extern size_t x509_der_cert_init_tv1_len;
extern size_t x509_der_cert_init_id_tv1_len;
extern size_t x509_auth_key_init_tv1_len;
extern size_t x509_der_cert_resp_tv1_len;
extern size_t x509_der_cert_resp_id_tv1_len;
extern size_t x509_auth_key_resp_tv1_len;

extern size_t rpk_cbor_init_tv2_len;
extern size_t rpk_cbor_init_id_tv2_len;
extern size_t rpk_auth_key_init_tv2_len;
extern size_t rpk_cbor_resp_tv2_len;
extern size_t rpk_cbor_resp_id_tv2_len;
extern size_t rpk_auth_key_resp_tv2_len;

extern size_t x509_der_cert_init_tv3_len;
extern size_t x509_der_cert_init_id_tv3_len;
extern size_t x509_auth_key_init_tv3_len;
extern size_t rpk_cbor_resp_tv3_len;
extern size_t rpk_cbor_resp_id_tv3_len;
extern size_t rpk_auth_key_resp_tv3_len;

extern size_t rpk_cbor_init_tv4_len;
extern size_t rpk_cbor_init_id_tv4_len;
extern size_t rpk_auth_key_init_tv4_len;
extern size_t x509_der_cert_resp_tv4_len;
extern size_t x509_der_cert_resp_id_tv4_len;
extern size_t x509_auth_key_resp_tv4_len;

int f_remote_creds(const uint8_t *key, size_t keyLen, const uint8_t **out, size_t *olen);
