#include <string.h>
#include <time.h>

#if defined(NANOCBOR)

#include <nanocbor/nanocbor.h>

#endif

#include "edhoc/edhoc.h"
#include "edhoc/cose.h"

#include "process.h"
#include "cipher_suites.h"
#include "crypto.h"
#include "format.h"
#include "cbor.h"


static void generate_conn_id(uint8_t *p, size_t *length) {
    size_t cidLen;

    srand(time(NULL));
    cidLen = rand() % (*length);

    for (size_t i = 0; i < cidLen; i++)
        p[i] = rand();

    *length = cidLen;
}


ssize_t edhoc_create_msg1(edhoc_ctx_t *ctx, corr_t corr, method_t m, cipher_suite_id_t id, uint8_t *out, size_t olen) {
    ssize_t ret, len;
    ssize_t ad1Len;

    uint8_t ad1Buf[EDHOC_ADDITIONAL_DATA_SIZE];

    edhoc_msg1_t msg1;

#if defined(WOLFSSL)
    wc_Sha256 hashCtx;
#elif defined(EMPTY_CRYPTO)
    int hashCtx;
#elif defined(HACL)
    hash_ctx_t hashCtx;
#elif
#error "No crypto backend enabled."
#endif

    const cipher_suite_t *suiteInfo;

    suiteInfo = NULL;

    format_msg1_init(&msg1);

    cose_key_init(&msg1.gX);

    if (ctx->state != EDHOC_WAITING) {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    if ((suiteInfo = edhoc_cipher_suite_from_id(id)) == NULL) {
        EDHOC_FAIL(EDHOC_ERR_CIPHERSUITE_UNAVAILABLE);
    }

    // setup EDHOC context
    ctx->session.cipherSuiteID = suiteInfo->id;
    ctx->correlation = corr;
    ctx->method = m;

    // initialize msg1 struct
    msg1.cipherSuite = suiteInfo;
    msg1.methodCorr = m * 4 + corr;

    // if not already initialized, generate and load ephemeral key
#if defined(EDHOC_DEBUG_ENABLED)
    if (ctx->myEphKey.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_SUCCESS(crypt_gen_keypair(suiteInfo->dhCurve, &ctx->myEphKey));
    }
#else
    EDHOC_CHECK_SUCCESS(crypt_gen_keypair(suiteInfo->dhCurve, &ctx->myEphKey));
#endif

    msg1.gX = ctx->myEphKey;

    if (ctx->session.cidiLen == 0) {
        ctx->session.cidiLen = EDHOC_CID_LEN;
        generate_conn_id(ctx->session.cidi, &ctx->session.cidiLen);
    }

    msg1.cidi.length = ctx->session.cidiLen;
    if (ctx->session.cidiLen == 1 && ctx->session.cidi[0] <= 0x2f)
        msg1.cidi.integer = ctx->session.cidi[0];
    else
        msg1.cidi.bstr = &ctx->session.cidi[0];

    if (ctx->conf->ad1 != NULL) {
        ctx->conf->ad1(ad1Buf, sizeof(ad1Buf), &ad1Len);
        msg1.ad1 = ad1Buf;
        msg1.ad1Len = ad1Len;
    } else {
        msg1.ad1 = NULL;
        msg1.ad1Len = 0;
    }

    if ((len = format_msg1_encode(&msg1, out, olen)) <= 0) {
        if (ret < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    // partial hash for th_2
    crypt_hash_init(&hashCtx);
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, len));
    EDHOC_CHECK_SUCCESS(crypt_copy_hash_context(ctx->thCtx, &hashCtx));

    if (ctx->state == EDHOC_WAITING) {
        ctx->state = EDHOC_SENT_MESSAGE_1;
    } else {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    ret = len;
    exit:
    return ret;
}

ssize_t edhoc_create_msg2(edhoc_ctx_t *ctx, const uint8_t *in, size_t ilen, uint8_t *out, size_t olen) {
    ssize_t ret, len;

    cred_t credCtx;
    ad_cb_t ad2;
    cred_type_t credType;

#if defined(WOLFSSL)
    wc_Sha256 hashCtx;
#elif defined(EMPTY_CRYPTO)
    int hashCtx;
#elif defined(HACL)
    hash_ctx_t hashCtx;
#else
#error "No crypto backend enabled"
#endif

#if defined(NANOCBOR)
    nanocbor_encoder_t enc;
#elif defined(EMPTY_CBOR)
    int enc;
#else
#error "No CBOR backend enabled"
#endif

    uint8_t iv2m[EDHOC_IV23M_SIZE];
    uint8_t mac2[EDHOC_MAC23_SIZE];
    uint8_t signature2[EDHOC_SIGNATURE23_SIZE];
    uint8_t p2e[EDHOC_PLAINTEXT23_SIZE];
    uint8_t keystream2[EDHOC_KEYSTREAM2_SIZE];

    // << TH_2, CRED_R, ? AD_2 >>
    uint8_t extData[EDHOC_EXTDATA_SIZE];

    edhoc_msg1_t msg1;
    edhoc_msg2_t msg2;
    edhoc_plaintext23_t plaintext2;

    cose_encrypt0_t innerCoseEncrypt0;
    cose_sign1_t coseSign1;
    cose_key_t k2m;

    const cose_aead_t *aeadCipher;
    const cose_sign_t *signAlgorithm;

    aeadCipher = NULL;
    signAlgorithm = NULL;

    format_msg1_init(&msg1);
    format_msg2_init(&msg2);
    format_plaintext23_init(&plaintext2);

    cose_key_init(&msg1.gX);
    cose_key_init(&msg2.data2.gY);
    cose_key_init(&k2m);

    if (ctx->state == EDHOC_WAITING) {
        ctx->state = EDHOC_RECEIVED_MESSAGE_1;
    } else {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    // (1) decode message 1 (checks if acceptable cipher suite)
    EDHOC_CHECK_SUCCESS(format_msg1_decode(&msg1, in, ilen));

    // setup method and correlation values
    ctx->correlation = msg1.methodCorr % 4;

    if (ctx->correlation < NO_CORR || ctx->correlation >= CORR_UNSET) {
        EDHOC_FAIL(EDHOC_ERR_UNSUPPORTED_CORR);
    }

    ctx->method = (msg1.methodCorr - ctx->correlation) / 4;
    ctx->session.cipherSuiteID = msg1.cipherSuite->id;

    // setup Initiator connection identifier
    if (msg1.cidi.length <= EDHOC_CID_LEN && msg1.cidi.length > 0) {
        // fetching security context
        ctx->session.cidiLen = msg1.cidi.length;

        if (ctx->session.cidiLen > 1)
            memcpy(ctx->session.cidi, msg1.cidi.bstr, ctx->session.cidiLen);
        else
            memcpy(ctx->session.cidi, &msg1.cidi.integer, ctx->session.cidiLen);

    } else {
        EDHOC_FAIL(EDHOC_ERR_BUFFER_OVERFLOW);
    }

    if (msg1.ad1Len != 0 && ctx->conf->ad1 != NULL) {
        // TODO: implement callbacks for ad1 delivery
    }

    // (2) generate data_2 and compute th_2
    msg2.data2.cidi.length = ctx->session.cidiLen;
    if (ctx->session.cidiLen > 1)
        msg2.data2.cidi.bstr = &ctx->session.cidi[0];
    else
        msg2.data2.cidi.integer = ctx->session.cidi[0];

#if defined(EDHOC_DEBUG_ENABLED)
    if (ctx->myEphKey.kty == COSE_KTY_NONE) {
        EDHOC_CHECK_SUCCESS(crypt_gen_keypair(msg1.cipherSuite->dhCurve, &msg2.data2.gY));
    }
#else
    EDHOC_CHECK_SUCCESS(crypt_gen_keypair(msg1.cipherSuite->dhCurve, &msg2.data2.gY));
#endif

    memcpy(&msg2.data2.gY, &ctx->myEphKey, sizeof(cose_key_t));

    if (ctx->session.cidrLen == 0) {
        ctx->session.cidrLen = EDHOC_CID_LEN;
        generate_conn_id(ctx->session.cidr, &ctx->session.cidrLen);
    }

    msg2.data2.cidr.length = ctx->session.cidrLen;
    if (ctx->session.cidrLen > 1)
        msg2.data2.cidr.bstr = &ctx->session.cidr[0];
    else
        msg2.data2.cidr.integer = ctx->session.cidr[0];


    if ((len = format_data2_encode(&msg2.data2, ctx->correlation, out, olen)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    // TH_2 = H ( msg1, data_2 )
    crypt_hash_init(&hashCtx);
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, in, ilen));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hashCtx, ctx->th2));

    // (3) compute the inner cose_encrypt0 - mac_2
    EDHOC_CHECK_SUCCESS(edhoc_compute_prk2e(&msg2.data2.gY, &msg1.gX, ctx->prk2e));
    EDHOC_CHECK_SUCCESS(
            edhoc_compute_prk3e2m(ctx->method, ctx->prk2e, ctx->conf->myCred.authKey, &msg1.gX, ctx->prk3e2m));

    if ((aeadCipher = cose_algo_get_aead_info(msg1.cipherSuite->aeadCipher)) == NULL) {
        EDHOC_FAIL(EDHOC_ERR_AEAD_CIPHER_UNAVAILABLE);
    }

    cose_encrypt0_init(&innerCoseEncrypt0, NULL, 0, aeadCipher, mac2);

    // create external data
    credCtx = ctx->conf->myCred.credCtx;
    credType = ctx->conf->myCred.credType;
    ad2 = ctx->conf->ad2;
    if ((len = format_external_data_encode(ctx->th2, credCtx, credType, ad2, extData, sizeof(extData))) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    cose_message_set_external_aad((cose_message_t *) &innerCoseEncrypt0, extData, len);
    cose_message_set_protected_hdr((cose_message_t *) &innerCoseEncrypt0, ctx->conf->myCred.idCtx->map);

    // compute the K_2m key
    EDHOC_CHECK_SUCCESS(edhoc_compute_K23mOrK3ae(aeadCipher, ctx->th2, ctx->prk3e2m, "K_2m", out, olen));
    cose_symmetric_key_from_buffer(&k2m, out, aeadCipher->keyLength);

    // compute the nonce
    EDHOC_CHECK_SUCCESS(edhoc_compute_IV23mOrIV3ae(aeadCipher, ctx->th2, ctx->prk3e2m, "IV_2m", out, olen));
    memcpy(iv2m, out, aeadCipher->ivLength);

    cose_encrypt0_encrypt(&innerCoseEncrypt0, &k2m, iv2m, aeadCipher->ivLength);

    if (ctx->method == EDHOC_AUTH_SIGN_SIGN || ctx->method == EDHOC_AUTH_STATIC_SIGN) {
        signAlgorithm = cose_algo_get_sign_info(msg1.cipherSuite->signAlgorithm);
        cose_sign1_init(&coseSign1, mac2, aeadCipher->tagLength, signAlgorithm, signature2);
        cose_message_set_protected_hdr((cose_message_t *) &coseSign1, ctx->conf->myCred.idCtx->map);
        cose_message_set_external_aad((cose_message_t *) &coseSign1, extData, len);

        EDHOC_CHECK_SUCCESS(cose_sign1_sign(&coseSign1, ctx->conf->myCred.authKey));

        plaintext2.sigOrMac23 = coseSign1.signature;
        plaintext2.sigOrMac23Len = coseSign1.sigLen;
    } else {
        plaintext2.sigOrMac23 = innerCoseEncrypt0.authTag;
        plaintext2.sigOrMac23Len = aeadCipher->tagLength;
    }

    plaintext2.credId = ctx->conf->myCred.idCtx;

    // TODO: handle the case where there is AD2
    plaintext2.ad23 = NULL;
    plaintext2.ad23Len = 0;

    if ((len = format_plaintext23_encode(&plaintext2, p2e, EDHOC_PLAINTEXT23_SIZE)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    EDHOC_CHECK_SUCCESS(edhoc_compute_keystream2(aeadCipher, ctx->th2, ctx->prk2e, "KEYSTREAM_2", len, out, olen));
    memcpy(keystream2, out, len);

    for (ssize_t i = 0; i < len; i++) {
        p2e[i] = p2e[i] ^ keystream2[i];
    }

    msg2.ciphertext2 = p2e;
    msg2.ciphertext2Len = len;

    // precomputed a part of TH_3 and store it in the EDHOC ctx
    crypt_hash_init(&hashCtx);
    cbor_init_encoder(&enc, out, olen);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, ctx->th2, EDHOC_DIGEST_SIZE));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, cbor_encoded_len(&enc)));

    cbor_init_encoder(&enc, out, olen);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, msg2.ciphertext2, msg2.ciphertext2Len));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, cbor_encoded_len(&enc)));

    EDHOC_CHECK_SUCCESS(crypt_copy_hash_context(ctx->thCtx, &hashCtx));

    if ((len = format_msg2_encode(&msg2, ctx->correlation, out, olen)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    if (ctx->state == EDHOC_RECEIVED_MESSAGE_1) {
        ctx->state = EDHOC_SENT_MESSAGE_2;
    } else {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    ret = len;
    exit:
    return ret;
}

ssize_t edhoc_create_msg3(edhoc_ctx_t *ctx, const uint8_t *in, size_t ilen, uint8_t *out, size_t olen) {
    ssize_t ret, len;
    int i;

    cred_t credCtx;
    ad_cb_t ad3;
    cred_type_t credType;
    cred_id_t remoteCredId;
    const uint8_t *remoteCred;
    size_t remoteCredLen;

#if defined(WOLFSSL)
    wc_Sha256 hashCtx;
#elif defined(EMPTY_X509)
    int hashCtx;
#elif defined(HACL)
    hash_ctx_t hashCtx;
#else
#error "No crypto backend enabled"
#endif

#if defined(NANOCBOR)
    nanocbor_encoder_t enc;
#elif defined(EMPTY_CBOR)
    int enc;
#else
#error "No CBOR backend enabled"
#endif

    uint8_t iv3mOrIv3ae[EDHOC_IV23M_SIZE];
    uint8_t mac3[EDHOC_MAC23_SIZE];
    uint8_t signature3[EDHOC_SIGNATURE23_SIZE];
    uint8_t keystream2[EDHOC_KEYSTREAM2_SIZE];
    uint8_t p2eOrP3ae[EDHOC_PLAINTEXT23_SIZE];
    uint8_t ciphertext3[EDHOC_PLAINTEXT23_SIZE + EDHOC_MAC23_SIZE];

    // << TH_3, CRED_I, ? AD_3 >>
    uint8_t extData[EDHOC_EXTDATA_SIZE];

    edhoc_msg3_t msg3;
    edhoc_msg2_t msg2;
    edhoc_plaintext23_t plaintext23;

    cose_encrypt0_t ioCoseEncrypt0;

    cose_sign1_t coseSign1;
    cose_key_t k3mOrk3ae;
    cose_key_t remoteAuthKey;

    const cose_aead_t *aeadCipher;
    const cipher_suite_t *cipherSuite;
    const cose_sign_t *signAlgorithm;

    cipherSuite = NULL;
    aeadCipher = NULL;
    signAlgorithm = NULL;

    cred_id_init(&remoteCredId);

    format_msg2_init(&msg2);
    format_msg3_init(&msg3);
    format_plaintext23_init(&plaintext23);

    cose_key_init(&k3mOrk3ae);
    cose_key_init(&remoteAuthKey);

    cipherSuite = edhoc_cipher_suite_from_id(ctx->session.cipherSuiteID);
    aeadCipher = cose_algo_get_aead_info(cipherSuite->aeadCipher);

    if (ctx->state == EDHOC_SENT_MESSAGE_1) {
        ctx->state = EDHOC_RECEIVED_MESSAGE_2;
    } else {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    EDHOC_CHECK_SUCCESS(format_msg2_decode(&msg2, ctx->correlation, cipherSuite, in, ilen));

    if (msg2.data2.cidr.length <= EDHOC_CID_LEN && msg2.data2.cidr.length > 0) {
        ctx->session.cidrLen = msg2.data2.cidr.length;

        if (ctx->session.cidrLen > 1)
            memcpy(ctx->session.cidr, msg2.data2.cidr.bstr, ctx->session.cidrLen);
        else
            memcpy(ctx->session.cidr, &msg2.data2.cidr.integer, ctx->session.cidrLen);
    } else {
        EDHOC_FAIL(EDHOC_ERR_BUFFER_OVERFLOW);
    }

    if ((len = format_data2_encode(&msg2.data2, ctx->correlation, out, olen)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    crypt_hash_init(&hashCtx);
    EDHOC_CHECK_SUCCESS(crypt_copy_hash_context(&hashCtx, ctx->thCtx));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hashCtx, ctx->th2));

    edhoc_compute_prk2e(&ctx->myEphKey, &msg2.data2.gY, ctx->prk2e);

    EDHOC_CHECK_SUCCESS(
            edhoc_compute_keystream2(aeadCipher, ctx->th2, ctx->prk2e, "KEYSTREAM_2", msg2.ciphertext2Len, out, olen));
    memcpy(keystream2, out, msg2.ciphertext2Len);

    for (size_t b = 0; b < msg2.ciphertext2Len; b++) {
        p2eOrP3ae[b] = msg2.ciphertext2[b] ^ keystream2[b];
    }

    plaintext23.credId = &remoteCredId;
    EDHOC_CHECK_SUCCESS(format_plaintext23_decode(&plaintext23, p2eOrP3ae, msg2.ciphertext2Len));

    // fetch the remote credential info
    for (i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        if (remoteCredId.map[i].key == COSE_HEADER_PARAM_X5T) {
            EDHOC_CHECK_SUCCESS(ctx->conf->f_remote_cred(remoteCredId.map[i].certHash.value,
                                                         remoteCredId.map[i].certHash.length,
                                                         &remoteCred,
                                                         &remoteCredLen));
            break;

        } else if (remoteCredId.map[i].key == COSE_HEADER_PARAM_KID) {
            if (remoteCredId.map[i].valueType == COSE_HDR_VALUE_BSTR) {
                EDHOC_CHECK_SUCCESS(ctx->conf->f_remote_cred(remoteCredId.map[i].bstr,
                                                             remoteCredId.map[i].len,
                                                             &remoteCred,
                                                             &remoteCredLen));
            } else if (remoteCredId.map[i].valueType == COSE_HDR_VALUE_INT) {
                if (remoteCredId.map[i].integer >= 0x0 && remoteCredId.map[i].integer <= 0x2f) {
                    EDHOC_CHECK_SUCCESS(ctx->conf->f_remote_cred((uint8_t *) &remoteCredId.map[i].integer,
                                                                 1,
                                                                 &remoteCred,
                                                                 &remoteCredLen));
                } else {
                    EDHOC_FAIL(EDHOC_ERR_INVALID_CRED_ID);
                }
            } else {
                EDHOC_FAIL(EDHOC_ERR_INVALID_CRED_ID);
            }
            cose_key_from_cbor(&remoteAuthKey, remoteCred, remoteCredLen);
            break;
        } else {
            continue;
        }
    }

    if (i == COSE_MAX_HEADER_ITEMS) {
        // couldn't find credential identifier
        EDHOC_FAIL(EDHOC_ERR_INVALID_CRED_ID);
    }

    if (ctx->method == EDHOC_AUTH_SIGN_SIGN || ctx->method == EDHOC_AUTH_SIGN_STATIC) {
        // TODO: verify certificate
    }

    EDHOC_CHECK_SUCCESS(
            edhoc_compute_prk3e2m(ctx->method, ctx->prk2e, &ctx->myEphKey, &remoteAuthKey, ctx->prk3e2m));

    // TODO: call the AD3 callback

    // compose message 3
    msg3.data3.cidr.length = ctx->session.cidrLen;
    if (ctx->session.cidrLen > 1)
        msg3.data3.cidr.bstr = &ctx->session.cidr[0];
    else
        msg3.data3.cidr.integer = ctx->session.cidr[0];

    // TH_3 = H(TH_2 , CIPHERTEXT_2, data_3)
    crypt_hash_init(&hashCtx);
    cbor_init_encoder(&enc, out, olen);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, ctx->th2, EDHOC_DIGEST_SIZE));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, cbor_encoded_len(&enc)));

    cbor_init_encoder(&enc, out, olen);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, msg2.ciphertext2, msg2.ciphertext2Len));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, cbor_encoded_len(&enc)));

    if ((len = format_data3_encode(&msg3.data3, ctx->correlation, out, olen)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hashCtx, ctx->th3));

    // (3) compute the inner cose_encrypt0 - mac_3
    EDHOC_CHECK_SUCCESS(edhoc_compute_prk4x3m(ctx->method, ctx->prk3e2m, ctx->conf->myCred.authKey, &msg2.data2.gY,
                                              ctx->session.prk4x3m));

    cose_encrypt0_init(&ioCoseEncrypt0, NULL, 0, aeadCipher, mac3);
    credCtx = ctx->conf->myCred.credCtx;
    credType = ctx->conf->myCred.credType;
    ad3 = ctx->conf->ad3;

    if ((len = format_external_data_encode(ctx->th3, credCtx, credType, ad3, extData, sizeof(extData))) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    cose_message_set_external_aad((cose_message_t *) &ioCoseEncrypt0, extData, len);
    cose_message_set_protected_hdr((cose_message_t *) &ioCoseEncrypt0, ctx->conf->myCred.idCtx->map);

    // compute the K_2m key
    EDHOC_CHECK_SUCCESS(edhoc_compute_K23mOrK3ae(aeadCipher, ctx->th3, ctx->session.prk4x3m, "K_3m", out, olen));
    cose_symmetric_key_from_buffer(&k3mOrk3ae, out, aeadCipher->keyLength);

    // compute the nonce
    EDHOC_CHECK_SUCCESS(edhoc_compute_IV23mOrIV3ae(aeadCipher, ctx->th3, ctx->session.prk4x3m, "IV_3m", out, olen));
    memcpy(iv3mOrIv3ae, out, aeadCipher->ivLength);

    cose_encrypt0_encrypt(&ioCoseEncrypt0, &k3mOrk3ae, iv3mOrIv3ae, aeadCipher->ivLength);

    // reset plaintext struct
    format_plaintext23_init(&plaintext23);
    if (ctx->method == EDHOC_AUTH_SIGN_SIGN || ctx->method == EDHOC_AUTH_SIGN_STATIC) {
        signAlgorithm = cose_algo_get_sign_info(cipherSuite->signAlgorithm);
        cose_sign1_init(&coseSign1, mac3, aeadCipher->tagLength, signAlgorithm, signature3);
        cose_message_set_protected_hdr((cose_message_t *) &coseSign1, ctx->conf->myCred.idCtx->map);
        cose_message_set_external_aad((cose_message_t *) &coseSign1, extData, len);

        EDHOC_CHECK_SUCCESS(cose_sign1_sign(&coseSign1, ctx->conf->myCred.authKey));

        plaintext23.sigOrMac23 = coseSign1.signature;
        plaintext23.sigOrMac23Len = coseSign1.sigLen;
    } else {
        plaintext23.sigOrMac23 = ioCoseEncrypt0.authTag;
        plaintext23.sigOrMac23Len = aeadCipher->tagLength;
    }

    plaintext23.credId = ctx->conf->myCred.idCtx;

    // TODO: handle the case where there is AD3
    plaintext23.ad23 = NULL;
    plaintext23.ad23Len = 0;

    if ((len = format_plaintext23_encode(&plaintext23, p2eOrP3ae, EDHOC_PLAINTEXT23_SIZE)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    // overwrite inner COSE Encrypt0 with outer COSE Encrypt0
    cose_encrypt0_init(&ioCoseEncrypt0, p2eOrP3ae, len, aeadCipher, mac3);
    cose_message_set_external_aad((cose_message_t *) &ioCoseEncrypt0, ctx->th3, EDHOC_DIGEST_SIZE);

    // reset cose key
    cose_key_init(&k3mOrk3ae);
    EDHOC_CHECK_SUCCESS(edhoc_compute_K23mOrK3ae(aeadCipher, ctx->th3, ctx->prk3e2m, "K_3ae", out, olen));
    cose_symmetric_key_from_buffer(&k3mOrk3ae, out, aeadCipher->keyLength);

    EDHOC_CHECK_SUCCESS(edhoc_compute_IV23mOrIV3ae(aeadCipher, ctx->th3, ctx->prk3e2m, "IV_3ae", out, olen));
    memcpy(iv3mOrIv3ae, out, aeadCipher->ivLength);

    cose_encrypt0_encrypt(&ioCoseEncrypt0, &k3mOrk3ae, iv3mOrIv3ae, aeadCipher->ivLength);
    memcpy(ciphertext3, ioCoseEncrypt0.base.payload, ioCoseEncrypt0.base.payloadLen);
    memcpy(ciphertext3 + ioCoseEncrypt0.base.payloadLen, ioCoseEncrypt0.authTag, aeadCipher->tagLength);

    msg3.ciphertext3 = ciphertext3;
    msg3.ciphertext3Len = ioCoseEncrypt0.base.payloadLen + aeadCipher->tagLength;

    // TH_4 = H( TH_3, CIPHERTEXT_3 ),
    crypt_hash_init(&hashCtx);
    cbor_init_encoder(&enc, out, olen);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, ctx->th3, EDHOC_DIGEST_SIZE));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, cbor_encoded_len(&enc)));

    cbor_init_encoder(&enc, out, olen);
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, msg3.ciphertext3, msg3.ciphertext3Len));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, out, cbor_encoded_len(&enc)));

    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hashCtx, ctx->session.th4));

    if ((len = format_msg3_encode(&msg3, ctx->correlation, out, olen)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    if (ctx->state == EDHOC_RECEIVED_MESSAGE_2) {
        ctx->state = EDHOC_SENT_MESSAGE_3;
    } else {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    ret = len;
    exit:
    return ret;
}

ssize_t edhoc_init_finalize(edhoc_ctx_t *ctx) {
    int ret;

    return ret;
}


ssize_t edhoc_resp_finalize(edhoc_ctx_t *ctx, const uint8_t *in, size_t ilen, bool msg4, uint8_t *out, size_t olen) {
    ssize_t ret, len;
    int i;

    cred_id_t remoteCredId;
    const uint8_t *remoteCred;
    size_t remoteCredLen;

#if defined(WOLFSSL)
    wc_Sha256 hashCtx;
#elif defined(EMPTY_X509)
    int hashCtx;
#elif defined(HACL)
    hash_ctx_t hashCtx;
#else
#error "No crypto backend enabled"
#endif

#if defined(NANOCBOR)
    nanocbor_encoder_t enc;
#elif defined(EMPTY_CBOR)
    int enc;
#else
#error "No CBOR backend enabled."
#endif

    uint8_t iv3ae[EDHOC_IV23M_SIZE];
    uint8_t temp[EDHOC_PLAINTEXT23_SIZE + EDHOC_MAC23_SIZE];

    edhoc_msg3_t msg3;
    edhoc_plaintext23_t plaintext3;

    cose_encrypt0_t outerCoseEncrypt0;

    cose_key_t k3ae;
    cose_key_t remoteAuthKey;

    const cose_aead_t *aeadCipher;
    const cipher_suite_t *cipherSuite;

    cipherSuite = NULL;
    aeadCipher = NULL;

    cred_id_init(&remoteCredId);

    format_msg3_init(&msg3);

    cose_key_init(&k3ae);
    cose_key_init(&remoteAuthKey);

    cipherSuite = edhoc_cipher_suite_from_id(ctx->session.cipherSuiteID);
    aeadCipher = cose_algo_get_aead_info(cipherSuite->aeadCipher);

    if (ctx->state == EDHOC_SENT_MESSAGE_2) {
        ctx->state = EDHOC_RECEIVED_MESSAGE_3;
    } else {
        ctx->state = EDHOC_FAILED;
        EDHOC_FAIL(EDHOC_ERR_ILLEGAL_STATE);
    }

    EDHOC_CHECK_SUCCESS(format_msg3_decode(&msg3, ctx->correlation, in, ilen));

    // TODO: retrieve security context

    // TH_3 = H(TH_2 , CIPHERTEXT_2, data_3)
    crypt_hash_init(&hashCtx);
    EDHOC_CHECK_SUCCESS(crypt_copy_hash_context(&hashCtx, ctx->thCtx));

    if ((len = format_data3_encode(&msg3.data3, ctx->correlation, temp, sizeof(temp))) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, temp, len));
    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hashCtx, ctx->th3));

    // TH_4 = H(TH_3 , CIPHERTEXT_3)
    crypt_hash_init(&hashCtx);
    cbor_init_encoder(&enc, temp, sizeof(temp));
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, ctx->th3, EDHOC_DIGEST_SIZE));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, temp, cbor_encoded_len(&enc)));

    cbor_init_encoder(&enc, temp, sizeof(temp));
    CBOR_ENC_CHECK_RET(cbor_put_bstr(&enc, msg3.ciphertext3, msg3.ciphertext3Len));
    EDHOC_CHECK_SUCCESS(crypt_hash_update(&hashCtx, temp, cbor_encoded_len(&enc)));

    EDHOC_CHECK_SUCCESS(crypt_hash_finish(&hashCtx, ctx->session.th4));

    EDHOC_CHECK_SUCCESS(edhoc_compute_K23mOrK3ae(aeadCipher, ctx->th3, ctx->prk3e2m, "K_3ae", temp, sizeof(temp)));
    cose_symmetric_key_from_buffer(&k3ae, temp, aeadCipher->keyLength);

    EDHOC_CHECK_SUCCESS(edhoc_compute_IV23mOrIV3ae(aeadCipher, ctx->th3, ctx->prk3e2m, "IV_3ae", temp, sizeof(temp)));
    memcpy(iv3ae, temp, aeadCipher->ivLength);

    memcpy(temp, msg3.ciphertext3, msg3.ciphertext3Len);

    cose_encrypt0_init(&outerCoseEncrypt0,
                       temp,
                       msg3.ciphertext3Len - aeadCipher->tagLength,
                       aeadCipher,
                       temp + msg3.ciphertext3Len - aeadCipher->tagLength);
    cose_message_set_external_aad((cose_message_t *) &outerCoseEncrypt0, ctx->th3, EDHOC_DIGEST_SIZE);

    EDHOC_CHECK_SUCCESS(cose_encrypt0_decrypt(&outerCoseEncrypt0, &k3ae, iv3ae, aeadCipher->ivLength));

    plaintext3.credId = &remoteCredId;
    EDHOC_CHECK_SUCCESS(
            format_plaintext23_decode(&plaintext3, outerCoseEncrypt0.base.payload, outerCoseEncrypt0.base.payloadLen));

    // fetch the remote credential info
    for (i = 0; i < COSE_MAX_HEADER_ITEMS; i++) {
        if (remoteCredId.map[i].key == COSE_HEADER_PARAM_X5T) {
            EDHOC_CHECK_SUCCESS(ctx->conf->f_remote_cred(remoteCredId.map[i].certHash.value,
                                                         remoteCredId.map[i].certHash.length,
                                                         &remoteCred,
                                                         &remoteCredLen));
            break;

        } else if (remoteCredId.map[i].key == COSE_HEADER_PARAM_KID) {
            if (remoteCredId.map[i].valueType == COSE_HDR_VALUE_BSTR) {
                EDHOC_CHECK_SUCCESS(ctx->conf->f_remote_cred(remoteCredId.map[i].bstr,
                                                             remoteCredId.map[i].len,
                                                             &remoteCred,
                                                             &remoteCredLen));
            } else if (remoteCredId.map[i].valueType == COSE_HDR_VALUE_INT) {
                if (remoteCredId.map[i].integer >= 0x0 && remoteCredId.map[i].integer <= 0x2f) {
                    EDHOC_CHECK_SUCCESS(ctx->conf->f_remote_cred((uint8_t *) &remoteCredId.map[i].integer,
                                                                 1,
                                                                 &remoteCred,
                                                                 &remoteCredLen));
                } else {
                    EDHOC_FAIL(EDHOC_ERR_INVALID_CRED_ID);
                }
            } else {
                EDHOC_FAIL(EDHOC_ERR_INVALID_CRED_ID);
            }
            cose_key_from_cbor(&remoteAuthKey, remoteCred, remoteCredLen);
            break;
        } else {
            continue;
        }
    }

    if (i == COSE_MAX_HEADER_ITEMS) {
        // couldn't find credential identifier
        EDHOC_FAIL(EDHOC_ERR_INVALID_CRED_ID);
    }

    if (ctx->method == EDHOC_AUTH_SIGN_SIGN || ctx->method == EDHOC_AUTH_SIGN_STATIC) {
        // TODO: verify certificate
    }

    // TODO: pass AD3 back to application

    EDHOC_CHECK_SUCCESS(
            edhoc_compute_prk4x3m(ctx->method, ctx->prk3e2m, &ctx->myEphKey, &remoteAuthKey, ctx->session.prk4x3m));

    exit:
    return ret;
}

ssize_t edhoc_create_error_msg(edhoc_ctx_t *ctx,
                               const char *diagMsg,
                               const uint8_t *suitesR,
                               size_t suitesRLen,
                               uint8_t *out,
                               size_t olen) {
    ssize_t ret, len;
    edhoc_error_msg_t errMsg;

    format_error_msg_init(&errMsg);

    if (ctx->conf->role == EDHOC_IS_RESPONDER) {
        errMsg.cid.length = ctx->session.cidrLen;
        if (ctx->session.cidrLen == 1 && ctx->session.cidr[0] <= 0x2f)
            errMsg.cid.integer = ctx->session.cidr[0];
        else
            errMsg.cid.bstr = &ctx->session.cidr[0];
    } else {
        errMsg.cid.length = ctx->session.cidiLen;
        if (ctx->session.cidiLen == 1 && ctx->session.cidi[0] <= 0x2f)
            errMsg.cid.integer = ctx->session.cidi[0];
        else
            errMsg.cid.bstr = &ctx->session.cidi[0];
    }

    errMsg.diagnosticMsg = diagMsg;
    errMsg.suitesR = suitesR;
    errMsg.suitesRLen = suitesRLen;

    if ((len = format_error_msg_encode(&errMsg, out, olen)) <= 0) {
        if (len < 0) {
            EDHOC_FAIL(len);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    ret = len;
    exit:
    return ret;
}

int edhoc_compute_K23mOrK3ae(const cose_aead_t *aeadInfo,
                             const uint8_t *th,
                             const uint8_t *prk,
                             const char *label,
                             uint8_t *out,
                             size_t olen) {

    int ret;
    uint8_t k23m[EDHOC_K23M_SIZE];

    if ((ret = format_info_encode(aeadInfo->id, th, label, aeadInfo->keyLength, out, olen)) <= 0) {
        if (ret < 0) {
            EDHOC_FAIL(ret);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    if ((ret = crypt_kdf(prk, out, ret, k23m, aeadInfo->keyLength))) {
        if (ret < 0) {
            EDHOC_FAIL(ret);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    // copy the result from the temporary buffer to the output buffer
    memcpy(out, k23m, aeadInfo->keyLength);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_compute_keystream2(const cose_aead_t *aeadInfo,
                             const uint8_t *th,
                             const uint8_t *prk,
                             const char *label,
                             size_t keyStreamLen,
                             uint8_t *out,
                             size_t olen) {
    int ret;
    uint8_t keystream2[EDHOC_KEYSTREAM2_SIZE];

    if ((ret = format_info_encode(aeadInfo->id, th, label, keyStreamLen, out, olen)) <= 0) {
        if (ret < 0) {
            EDHOC_FAIL(ret);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    if ((ret = crypt_kdf(prk, out, ret, keystream2, keyStreamLen))) {
        if (ret < 0) {
            EDHOC_FAIL(ret);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    // copy the result from the temporary buffer to the output buffer
    memcpy(out, keystream2, keyStreamLen);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_compute_IV23mOrIV3ae(const cose_aead_t *aeadInfo,
                               const uint8_t *th,
                               const uint8_t *prk,
                               const char *label,
                               uint8_t *out,
                               size_t olen) {

    int ret;
    uint8_t iv23m[EDHOC_IV23M_SIZE];

    if ((ret = format_info_encode(aeadInfo->id, th, label, aeadInfo->ivLength, out, olen)) <= 0) {
        if (ret < 0) {
            EDHOC_FAIL(ret);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    if ((ret = crypt_kdf(prk, out, ret, iv23m, aeadInfo->ivLength))) {
        if (ret < 0) {
            EDHOC_FAIL(ret);
        } else {
            EDHOC_FAIL(EDHOC_ERR_INVALID_SIZE);
        }
    }

    // copy the result from the temporary buffer to the output buffer
    memcpy(out, iv23m, aeadInfo->ivLength);

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_compute_prk2e(const cose_key_t *sk, const cose_key_t *pk, uint8_t *prk_2e) {
    return crypt_derive_prk(sk, pk, NULL, 0, prk_2e);
}

int edhoc_compute_prk3e2m(method_t m,
                          const uint8_t *prk2e,
                          const cose_key_t *sk,
                          const cose_key_t *pk,
                          uint8_t *prk3e2m) {
    int ret;

    switch (m) {
        case EDHOC_AUTH_SIGN_SIGN:
        case EDHOC_AUTH_STATIC_SIGN:
            memcpy(prk3e2m, prk2e, EDHOC_DIGEST_SIZE);
            break;
        case EDHOC_AUTH_STATIC_STATIC:
        case EDHOC_AUTH_SIGN_STATIC:
            crypt_derive_prk(sk, pk, prk2e, EDHOC_DIGEST_SIZE, prk3e2m);
            break;
        default:
            ret = EDHOC_ERR_CRYPTO;
            goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}

int edhoc_compute_prk4x3m(method_t m,
                          const uint8_t *prk3e2m,
                          const cose_key_t *sk,
                          const cose_key_t *pk,
                          uint8_t *prk4x3m) {
    int ret;

    switch (m) {
        case EDHOC_AUTH_SIGN_SIGN:
        case EDHOC_AUTH_SIGN_STATIC:
            memcpy(prk4x3m, prk3e2m, EDHOC_DIGEST_SIZE);
            break;
        case EDHOC_AUTH_STATIC_STATIC:
        case EDHOC_AUTH_STATIC_SIGN:
            crypt_derive_prk(sk, pk, prk3e2m, EDHOC_DIGEST_SIZE, prk4x3m);
            break;
        default:
            ret = EDHOC_ERR_CRYPTO;
            goto exit;
    }

    ret = EDHOC_SUCCESS;
    exit:
    return ret;
}
