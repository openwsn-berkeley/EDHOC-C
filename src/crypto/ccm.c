/**
 * @brief AES CCM implementation
 *
 * @author Marcelo Barros de Almeida <marcelobarrosalmeida@gmail.com>, March 2015.
 * @author Malisa Vucinic <malishav@gmail.com>, June 2017.
 * @author Timothy Claeys <timothy.claeys@gmail.com>, January 2021
*/

#include <string.h>
#include <stdint.h>

#include "ccm.h"
#include "aes128.h"

#define CBC_MAX_MAC_SIZE        (16)


/**
 * @brief Raw AES-CBC encryption.
 *
 * @param[in,out] buffer    Message to be encrypted. Will be overwritten by ciphertext.
 * @param[in] len           Message length. Must be multiple of 16 octets.
 * @param[in] key           Buffer containing the secret key (16 octets).
 * @param[in] iv            Buffer containing the Initialization Vector (16 octets).
 *
 * @returns EDHOC_SUCCESS when the encryption was successful.
*/
int aes_cbc_enc_raw(uint8_t *buffer, size_t len, uint8_t key[16], uint8_t iv[16]) {
    size_t n;
    uint8_t k;
    size_t nb;
    uint8_t *pbuf;
    uint8_t *pxor;

    nb = len >> 4;
    pxor = iv;
    for (n = 0; n < nb; n++) {
        pbuf = &buffer[16 * n];
        // may be faster if vector are aligned to 4 bytes (use long instead char in xor)
        for (k = 0; k < 16; k++) {
            pbuf[k] ^= pxor[k];
        }
        aes128_enc(pbuf, key);
        pxor = pbuf;
    }
    return EDHOC_SUCCESS;
}

static void inc_counter(uint8_t *counter) {
    // from openssl
    size_t n = 16;
    uint8_t c;
    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}

/**
 * @brief Raw AES-CTR encryption.
 *
 * @param[in,out] buffer    Message to be encrypted. Will be overwritten by ciphertext.
 * @param[in] len           Message length. Must be multiple of 16 octets.
 * @param[in] key           Buffer containing the secret key (16 octets).
 * @param[in] iv            Buffer containing the Initialization Vector (16 octets).
 *
 * @return EDHOC_SUCCESS when the encryption was successful.
*/
int aes_ctr_enc_raw(uint8_t *buffer, size_t len, uint8_t key[16], uint8_t iv[16]) {
    size_t n;
    uint8_t k;
    size_t nb;
    uint8_t *pbuf;
    uint8_t eiv[16];

    nb = len >> 4;
    for (n = 0; n < nb; n++) {
        pbuf = &buffer[16 * n];
        memcpy(eiv, iv, 16);
        aes128_enc(eiv, key);
        // may be faster if vector are aligned to 4 bytes (use long instead char in xor)
        for (k = 0; k < 16; k++) {
            pbuf[k] ^= eiv[k];
        }
        inc_counter(iv);
    }

    return EDHOC_SUCCESS;
}

/**
 * @brief CBC-MAC generation specific to CCM.
 *
 * @param[in] a         Pointer to the authentication only data.
 * @param[in] len_a     Length of authentication only data.
 * @param[in] m         Pointer to the data that is both authenticated and encrypted.
 * @param[in] len_m     Length of data that is both authenticated and encrypted.
 * @param[in] nonce     Buffer containing nonce (13 octets).
 * @param[in] key       Buffer containing the secret key (16 octets).
 * @param[out] mac      Buffer where the value of the CBC-MAC tag will be written.
 * @param[in] len_mac   Length of the CBC-MAC tag. Must be 4, 8 or 16 octets.
 * @param[in] l         CCM parameter L that allows selection of different nonce length.
 *
 * @returns EDHOC_SUCCESS when the generation was successful, EDHOC_ERR_CRYPTO otherwise.
*/
static int aes_cbc_mac(uint8_t *a,
                       size_t len_a,
                       uint8_t *m,
                       size_t len_m,
                       uint8_t *nonce,
                       uint8_t key[16],
                       uint8_t *mac,
                       size_t len_mac,
                       uint8_t l) {

    size_t pad_len;
    size_t len;
    uint8_t cbc_mac_iv[16];
    uint8_t buffer[512]; // max buffer plus IV

    // asserts here
    if (!((len_mac == 0) || (len_mac == 4) || (len_mac == 8) || (len_mac == 16))) {
        return EDHOC_ERR_CRYPTO;
    }

    // if ((len_a > 127) || (len_m > 127) || ((len_a + len_m) > 127)) {
    //     return EDHOC_ERR_CRYPTO;
    // }

    if (mac == NULL) {
        return EDHOC_ERR_CRYPTO;
    }

    // CBC-MAC Initialization Vector is a zero string
    memset(cbc_mac_iv, 0, 16);

    // IV: flags (1B) | SADDR (8B) | ASN (5B) | len(m) (2B)
    // X0 xor IV in first 16 bytes of buffer: set buffer[:16] as IV)

    buffer[0] = 0x00;                           // set flags to zero including reserved
    buffer[0] |= 0x07 & (l - 1);                // field L

    // (len_mac - 2)/2 shifted left 3 times corresponds to (len_mac - 2) << 2
    buffer[0] |= len_mac == 0 ? 0 : (0x07 & (len_mac - 2)) << 2;    // field M
    buffer[0] |= len_a != 0 ? 0x40 : 0;                             // field Adata

    memcpy(&buffer[1], nonce, 13);

    if (l == 3) {
        buffer[13] = 0;
    }

    buffer[14] = ((len_m & 0xFF00) >> 8);
    buffer[15] = (len_m & 0x00FF);

    len = 16;
    // len(a)
    if (len_a > 0) {
        buffer[16] = ((len_a & 0xFF00) >> 8);
        buffer[17] = (len_a & 0x00FF);
        len += 2;
    }

    //  (((x >> 4) + 1)<<4) - x   or    16 - (x % 16) ?
    // a + padding
    pad_len = ((((len_a + len - 16) >> 4) + 1) << 4) - (len_a + len - 16);
    pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], a, len_a);
    len += len_a;
    memset(&buffer[len], 0, pad_len);
    len += pad_len;

    // m + padding
    pad_len = (((len_m >> 4) + 1) << 4) - len_m;
    pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], m, len_m);
    len += len_m;
    memset(&buffer[len], 0, pad_len);
    len += pad_len;

    aes_cbc_enc_raw(buffer, len, key, cbc_mac_iv);

    // copy MAC
    memcpy(mac, &buffer[len - 16], len_mac);

    return EDHOC_SUCCESS;
}

/**
 * @brief Counter (CTR) mode encryption specific to IEEE 802.15.4E.
 *
 * @param[in,out] m     Pointer to the data that is both authenticated and encrypted. Data is overwritten by ciphertext
 * (i.e. plaintext in case of inverse CCM*).
 * @param[in] len_m     Length of data that is both authenticated and encrypted.
 * @param[in] nonce     Buffer containing nonce (13 octets).
 * @param[in] key       Buffer containing the secret key (16 octets).
 * @param[in,out] mac   Buffer containing the unencrypted or encrypted CBC-MAC tag, which depends on weather the function
 * is called as part of CCM* forward or inverse transformation. It is overwrriten by the encrypted, i.e unencrypted,
 * tag on return.
 * @param[in] len_mac   Length of the CBC-MAC tag. Must be 4, 8 or 16 octets.
 * @param[in] l         CCM parameter L that allows selection of different nonce length.
 *
 * @returns EDHOC_SUCCESS when the encryption was successful, EDHOC_ERR_CRYPTO otherwise.
*/
static int aes_ctr_enc(uint8_t *m,
                       size_t len_m,
                       uint8_t *nonce,
                       uint8_t key[16],
                       uint8_t *mac,
                       size_t len_mac,
                       uint8_t l) {

    size_t pad_len;
    size_t len;
    uint8_t iv[16];
    uint8_t buffer[512]; // max buffer plus mac

    // asserts here
    if (!((len_mac == 0) || (len_mac == 4) || (len_mac == 8) || (len_mac == 16))) {
        return EDHOC_ERR_CRYPTO;
    }

    // if (len_m > 127) {
    //     return EDHOC_ERR_CRYPTO;
    // }

    // iv (flag (1B) | source addr (8B) | ASN (5B) | cnt (2B)
    iv[0] = 0x00;
    iv[0] |= 0x07 & (l - 1); // field L

    memcpy(&iv[1], nonce, 13);
    iv[14] = 0x00;
    iv[15] = 0x00;

    // first block is mac
    memcpy(buffer, mac, len_mac);
    memset(&buffer[len_mac], 0, 16 - len_mac);
    len = 16;

    //  (((x >> 4) + 1)<<4) - x   or    16 - (x % 16) ?
    // m + padding
    pad_len = (((len_m >> 4) + 1) << 4) - len_m;
    pad_len = pad_len == 16 ? 0 : pad_len;
    memcpy(&buffer[len], m, len_m);
    len += len_m;
    memset(&buffer[len], 0, pad_len);
    len += pad_len;

    aes_ctr_enc_raw(buffer, len, key, iv);

    memcpy(m, &buffer[16], len_m);
    memcpy(mac, buffer, len_mac);

    return EDHOC_SUCCESS;
}


int aes128_ccms_enc(uint8_t *a,
                    size_t len_a,
                    uint8_t *m,
                    size_t *len_m,
                    uint8_t *nonce,
                    uint8_t l,
                    uint8_t key[16],
                    size_t len_mac) {

    uint8_t mac[CBC_MAX_MAC_SIZE];

    if ((len_mac > CBC_MAX_MAC_SIZE) || (l != 2)) {
        return EDHOC_ERR_CRYPTO;
    }

    if (aes_cbc_mac(a, len_a, m, *len_m, nonce, key, mac, len_mac, l) == EDHOC_SUCCESS) {
        if (aes_ctr_enc(m, *len_m, nonce, key, mac, len_mac, l) == EDHOC_SUCCESS) {
            memcpy(&m[*len_m], mac, len_mac);
            *len_m += len_mac;

            return EDHOC_SUCCESS;
        }
    }

    return EDHOC_ERR_CRYPTO;
}

int aes128_ccms_dec(uint8_t *a,
                    size_t len_a,
                    uint8_t *m,
                    size_t *len_m,
                    uint8_t *nonce,
                    uint8_t l,
                    uint8_t key[16],
                    size_t len_mac) {

    uint8_t mac[CBC_MAX_MAC_SIZE];
    uint8_t orig_mac[CBC_MAX_MAC_SIZE];

    if ((len_mac > CBC_MAX_MAC_SIZE) || (l != 2)) {
        return EDHOC_ERR_CRYPTO;
    }

    *len_m -= len_mac;
    memcpy(mac, &m[*len_m], len_mac);

    if (aes_ctr_enc(m, *len_m, nonce, key, mac, len_mac, l) == EDHOC_SUCCESS) {
        if (aes_cbc_mac(a, len_a, m, *len_m, nonce, key, orig_mac, len_mac, l) == EDHOC_SUCCESS) {
            if (memcmp(mac, orig_mac, len_mac) == 0) {
                return EDHOC_SUCCESS;
            }
        }
    }

    return EDHOC_ERR_CRYPTO;
}

