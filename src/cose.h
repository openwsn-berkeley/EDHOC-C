#ifndef EDHOC_COSE_H
#define EDHOC_COSE_H

#if !defined(EDHOC_CONFIG_FILE)

#include "edhoc/config.h"

#else
#include EDHOC_CONFIG_FILE
#endif

#include <stdint.h>
#include <stdlib.h>

#include "edhoc/edhoc.h"

typedef enum {
    COSE_HEADER_MAP_PARAM_ALG = 1,
    COSE_HEADER_MAP_PARAM_CRIT = 2,
    COSE_HEADER_MAP_PARAM_CTYPE = 3,
    COSE_HEADER_MAP_PARAM_KID = 4
} cose_header_map_param_t;

typedef enum {
    COSE_KEY_COMMON_PARAM_KTY = 1,        /**< Key type identifier */
    COSE_KEY_COMMON_PARAM_KID = 2,        /**< Key identifier */
    COSE_KEY_COMMON_PARAM_ALGO = 3,       /**< Key algorithm */
    COSE_KEY_COMMON_PARAM_OPS = 4,        /**< Key options */
    COSE_KEY_COMMON_PARAM_BIV = 5,        /**< Base IV */
    COSE_KEY_COMMON_PARAM_X5CHAIN = 33,   /**< An ordered chain of X.509 certificates */
    COSE_KEY_COMMON_PARAM_X5T = 34,       /**< Hash of an X.509 certificate */
    COSE_KEY_COMMON_PARAM_URI = 35,       /**< URI pointing to an X.509 certificate */
} cose_key_common_param_t;

/**
 * @brief COSE EC2 key parameters
 */
typedef enum {
    COSE_KEY_EC2_PARAM_CRV = -1,    /**< Key type identifier */
    COSE_KEY_EC2_PARAM_X = -2,      /**< Key identifier */
    COSE_KEY_EC2_PARAM_Y = -3,      /**< Key algorithm */
    COSE_KEY_EC2_PARAM_D = -4,      /**< Key options */
} cose_key_ec2_param_t;

/**
 * @brief COSE octet key parameters
 */
typedef enum {
    COSE_KEY_OKP_PARAM_CRV = -1,    /**< Key type identifier */
    COSE_KEY_OKP_PARAM_X = -2,      /**< Key identifier */
    COSE_KEY_OKP_PARAM_D = -4,      /**< Key options */
} cose_key_okp_param_t;

typedef struct aead_info_t aead_info_t;

struct aead_info_t {
    uint8_t id;
    const char *name;
    uint8_t key_length;
    uint8_t iv_length;
    uint8_t tag_length;
};

/**
 * @brief   Initializes a COSE key object, must be called before using the key
 * object
 *
 * @param[in,out] key      Key object to initialize
 */
void cose_key_init(cose_key_t *key);

/**
 * @brief   Returns an AEAD cipher information structure based on its identifier
 *
 * @param[in] aead_id   COSE identifier of the AEAD cipher
 *
 * @return On success returns an AEAD cipher information structure
 * @return On failure returns NULL
 */
const aead_info_t *cose_aead_info_from_id(uint8_t aead_id);

/**
 * @brief   Initializes a key struct based on a cbor map
 *
 * @param[out] key          Initialized COSE key struct to fill with key information
 * @param[in] key_bytes     Array of bytes containing the CBOR encoded key
 * @param[in] key_len       Length of @p key_bytes
 *
 * @return  On success return EDHOC_SUCCESS
 * @return  On failure a negative value
 */
int cose_key_from_cbor(cose_key_t *key, const unsigned char *key_bytes, size_t key_len);


#endif /* EDHOC_COSE_H */
