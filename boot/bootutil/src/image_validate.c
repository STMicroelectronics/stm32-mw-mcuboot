/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2017-2019 Linaro LTD
 * Copyright (c) 2016-2019 JUUL Labs
 * Copyright (c) 2019-2024 Arm Limited
 * Copyright (c) 2023-2025 STMicroelectronics
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <flash_map_backend.h>

#include "bootutil/bootutil_log.h"
#include "bootutil/image.h"
#include "bootutil/crypto/sha.h"
#include "bootutil/sign_key.h"
#include "bootutil/security_cnt.h"
#include "bootutil/fault_injection_hardening.h"

#include "mcuboot_config.h"

#ifdef MCUBOOT_ENC_IMAGES
#include "bootutil/enc_key.h"
#endif
#if defined(MCUBOOT_SIGN_RSA)
#include "mbedtls/rsa.h"
#endif
#if defined(MCUBOOT_SIGN_EC256)
#include "mbedtls/ecdsa.h"
#endif
#if defined(MCUBOOT_ENC_IMAGES) || defined(MCUBOOT_SIGN_RSA) || \
    defined(MCUBOOT_SIGN_EC256)
#include "mbedtls/asn1.h"
#endif

#include "bootutil_priv.h"

#ifdef MCUBOOT_DOUBLE_SIGN_VERIF
#include "boot_hal_imagevalid.h"
#endif
#ifdef MCUBOOT_USE_HASH_REF
#include "boot_hal_hash_ref.h"
#endif

#include "bootutil_misc.h"

#ifndef FLASH_ERASED_BYTE_VAL
#define FLASH_ERASED_BYTE_VAL 0xff
#endif
#ifndef FLASH_ERASED_DOUBLEWORD_VAL
#define FLASH_ERASED_DOUBLEWORD_VAL 0xffffffffffffffff
#endif

/*
 * Compute SHA hash over the image.
 * (SHA384 if ECDSA-P384 is being used,
 *  SHA256 otherwise).
 */
static int
bootutil_img_hash(struct enc_key_data *enc_state, int image_index,
                  struct image_header *hdr, const struct flash_area *fap,
                  uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *hash_result,
                  uint8_t *seed, int seed_len)
{
    bootutil_sha_context sha_ctx;
    uint32_t blk_sz;
    uint32_t size;
    uint16_t hdr_size;
    uint32_t off;
    int rc;
    uint32_t blk_off;
    uint32_t tlv_off;

#if (BOOT_IMAGE_NUMBER == 1) || !defined(MCUBOOT_ENC_IMAGES) || \
    defined(MCUBOOT_RAM_LOAD)
    (void)enc_state;
    (void)image_index;
    (void)hdr_size;
    (void)blk_off;
    (void)tlv_off;
#ifdef MCUBOOT_RAM_LOAD
    (void)blk_sz;
    (void)off;
    (void)rc;
    (void)fap;
    (void)tmp_buf;
    (void)tmp_buf_sz;
#endif
#endif

#ifdef MCUBOOT_ENC_IMAGES
    /* Encrypted images only exist in the secondary slot */
    if (MUST_DECRYPT(fap, image_index, hdr) &&
        !boot_enc_valid(enc_state, image_index, fap)) {
        return -1;
    }
#endif

    bootutil_sha_init(&sha_ctx);

    /* in some cases (split image) the hash is seeded with data from
     * the loader image */
    if (seed && (seed_len > 0)) {
        bootutil_sha_update(&sha_ctx, seed, seed_len);
    }

    /* Hash is computed over image header and image itself. */
    size = hdr_size = hdr->ih_hdr_size;
    size += hdr->ih_img_size;
    tlv_off = size;

    /* If protected TLVs are present they are also hashed. */
    size += hdr->ih_protect_tlv_size;

#ifdef MCUBOOT_RAM_LOAD
    bootutil_sha_update(&sha_ctx,
                        (void*)(IMAGE_RAM_BASE + hdr->ih_load_addr),
                        size);
#else
    for (off = 0; off < size; off += blk_sz) {
        blk_sz = size - off;
        if (blk_sz > tmp_buf_sz) {
            blk_sz = tmp_buf_sz;
        }
#ifdef MCUBOOT_ENC_IMAGES
        /* The only data that is encrypted in an image is the payload;
         * both header and TLVs (when protected) are not.
         */
        if ((off < hdr_size) && ((off + blk_sz) > hdr_size)) {
            /* read only the header */
            blk_sz = hdr_size - off;
        }
        if ((off < tlv_off) && ((off + blk_sz) > tlv_off)) {
            /* read only up to the end of the image payload */
            blk_sz = tlv_off - off;
        }
#endif
        rc = flash_area_read(fap, off, tmp_buf, blk_sz);
        if (rc) {
            bootutil_sha_drop(&sha_ctx);
            return rc;
        }
#ifdef MCUBOOT_ENC_IMAGES
        if (MUST_DECRYPT(fap, image_index, hdr)) {
            /* Only payload is encrypted (area between header and TLVs) */
            if (off >= hdr_size && off < tlv_off) {
                blk_off = (off - hdr_size) & 0xf;
                boot_encrypt(enc_state, image_index, fap, off - hdr_size,
                        blk_sz, blk_off, tmp_buf);
            }
        }
#endif
        bootutil_sha_update(&sha_ctx, tmp_buf, blk_sz);
    }
#endif /* MCUBOOT_RAM_LOAD */
    bootutil_sha_finish(&sha_ctx, hash_result);
    bootutil_sha_drop(&sha_ctx);

    return 0;
}

/*
 * Currently, we only support being able to verify one type of
 * signature, because there is a single verification function that we
 * call.  List the type of TLV we are expecting.  If we aren't
 * configured for any signature, don't define this macro.
 */
#if (defined(MCUBOOT_SIGN_RSA)      + \
     defined(MCUBOOT_SIGN_EC256)    + \
     defined(MCUBOOT_SIGN_EC384)    + \
     defined(MCUBOOT_SIGN_ED25519)) > 1
#error "Only a single signature type is supported!"
#endif

#if defined(MCUBOOT_SIGN_RSA)
#    if MCUBOOT_SIGN_RSA_LEN == 2048
#        define EXPECTED_SIG_TLV IMAGE_TLV_RSA2048_PSS
#    elif MCUBOOT_SIGN_RSA_LEN == 3072
#        define EXPECTED_SIG_TLV IMAGE_TLV_RSA3072_PSS
#    else
#        error "Unsupported RSA signature length"
#    endif
#    define SIG_BUF_SIZE (MCUBOOT_SIGN_RSA_LEN / 8)
#    define EXPECTED_SIG_LEN(x) ((x) == SIG_BUF_SIZE) /* 2048 bits */
#elif defined(MCUBOOT_SIGN_EC256) || \
      defined(MCUBOOT_SIGN_EC384) || \
      defined(MCUBOOT_SIGN_EC)
#    define EXPECTED_SIG_TLV IMAGE_TLV_ECDSA_SIG
#    define SIG_BUF_SIZE 128
#if defined(MCUBOOT_SIGN_EC256)
#    define EXPECTED_SIG_LEN(x) ((x) <= 72)
#    define EXPECTED_PUBKEY_LEN 91
#elif defined(MCUBOOT_SIGN_EC384)
#    define EXPECTED_SIG_LEN(x) ((x) <= 104)
#    define EXPECTED_PUBKEY_LEN 120
#else
#    error "Unsupported EC signature"
#endif
#elif defined(MCUBOOT_SIGN_ED25519)
#    define EXPECTED_SIG_TLV IMAGE_TLV_ED25519
#    define SIG_BUF_SIZE 64
#    define EXPECTED_SIG_LEN(x) ((x) == SIG_BUF_SIZE)
#else
#    define SIG_BUF_SIZE 32 /* no signing, sha256 digest only */
#endif

#if (defined(MCUBOOT_HW_KEY)       + \
     defined(MCUBOOT_BUILTIN_KEY)) > 1
#error "Please use either MCUBOOT_HW_KEY or the MCUBOOT_BUILTIN_KEY feature."
#endif

#ifdef EXPECTED_SIG_TLV

#if !defined(MCUBOOT_BUILTIN_KEY)
#if !defined(MCUBOOT_HW_KEY)
/* The key TLV contains the hash of the public key. */
#   define EXPECTED_KEY_TLV     IMAGE_TLV_KEYHASH
#   define KEY_BUF_SIZE         IMAGE_HASH_SIZE
#else
/* The key TLV contains the whole public key.
 * Add a few extra bytes to the key buffer size for encoding and
 * for public exponent.
 */
#   define EXPECTED_KEY_TLV     IMAGE_TLV_PUBKEY
#   define KEY_BUF_SIZE         (SIG_BUF_SIZE + 24)
#endif /* !MCUBOOT_HW_KEY */

#if !defined(MCUBOOT_HW_KEY)
static int
bootutil_find_key(uint8_t image_index, uint8_t *keyhash, uint8_t keyhash_len)
{
    bootutil_sha_context sha_ctx;
    const struct bootutil_key *key;
    uint8_t hash[IMAGE_HASH_SIZE];

    if (keyhash_len > IMAGE_HASH_SIZE) {
        return -1;
    }

    /* Check image_size parameter */
    if (image_index >= bootutil_key_cnt) {
        return -1;
    }

    key = &bootutil_keys[image_index];
    bootutil_sha_init(&sha_ctx);
    bootutil_sha_update(&sha_ctx, key->key, *key->len);
    bootutil_sha_finish(&sha_ctx, hash);
    if (!memcmp(hash, keyhash, keyhash_len)) {
        bootutil_sha_drop(&sha_ctx);
        return (int)image_index;
    }
    bootutil_sha_drop(&sha_ctx);
    return -1;
}
#else /* !MCUBOOT_HW_KEY */
extern unsigned int pub_key_len;
static int
bootutil_find_key(uint8_t image_index, uint8_t *key, uint16_t key_len)
{
    bootutil_sha_context sha_ctx;
    uint8_t hash[IMAGE_HASH_SIZE];
    uint8_t key_hash[IMAGE_HASH_SIZE];
    size_t key_hash_size = sizeof(key_hash);
    int rc;
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    bootutil_sha_init(&sha_ctx);
    bootutil_sha_update(&sha_ctx, key, key_len);
    bootutil_sha_finish(&sha_ctx, hash);
    bootutil_sha_drop(&sha_ctx);

    rc = boot_retrieve_public_key_hash(image_index, key_hash, &key_hash_size);
    if (rc) {
        return -1;
    }

    /* Adding hardening to avoid this potential attack:
     *  - Image is signed with an arbitrary key and the corresponding public
     *    key is added as a TLV field.
     * - During public key validation (comparing against key-hash read from
     *   HW) a fault is injected to accept the public key as valid one.
     */
    FIH_CALL(boot_fih_memequal, fih_rc, hash, key_hash, key_hash_size);
    if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
        bootutil_keys[0].key = key;
        pub_key_len = key_len;
        return 0;
    }

    return -1;
}
#endif /* !MCUBOOT_HW_KEY */
#endif /* !MCUBOOT_BUILTIN_KEY */
#endif /* EXPECTED_SIG_TLV */

/**
 * Reads the value of an image's security counter.
 *
 * @param hdr           Pointer to the image header structure.
 * @param fap           Pointer to a description structure of the image's
 *                      flash area.
 * @param security_cnt  Pointer to store the security counter value.
 *
 * @return              0 on success; nonzero on failure.
 */
int32_t
bootutil_get_img_security_cnt(struct image_header *hdr,
                              const struct flash_area *fap,
                              uint32_t *img_security_cnt)
{
    struct image_tlv_iter it;
    uint32_t off;
    uint16_t len;
    int32_t rc;

    if ((hdr == NULL) ||
        (fap == NULL) ||
        (img_security_cnt == NULL)) {
        /* Invalid parameter. */
        return BOOT_EBADARGS;
    }

    /* The security counter TLV is in the protected part of the TLV area. */
    if (hdr->ih_protect_tlv_size == 0) {
        return BOOT_EBADIMAGE;
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_SEC_CNT, true);
    if (rc) {
        return rc;
    }

    /* Traverse through the protected TLV area to find
     * the security counter TLV.
     */

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0) {
        /* Security counter TLV has not been found. */
        return -1;
    }

    if (len != sizeof(*img_security_cnt)) {
        /* Security counter is not valid. */
        return BOOT_EBADIMAGE;
    }

    rc = LOAD_IMAGE_DATA(hdr, fap, off, img_security_cnt, len);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    return 0;
}

#ifndef ALLOW_ROGUE_TLVS
/*
 * The following list of TLVs are the only entries allowed in the unprotected
 * TLV section.  All other TLV entries must be in the protected section.
 */
static const uint16_t allowed_unprot_tlvs[] = {
#ifdef EXPECTED_KEY_TLV
     EXPECTED_KEY_TLV,
#endif
#ifdef EXPECTED_HASH_TLV
     EXPECTED_HASH_TLV,
#endif
#ifdef EXPECTED_SIG_TLV
     EXPECTED_SIG_TLV,
#endif
#ifdef EXPECTED_ENC_TLV
     EXPECTED_ENC_TLV,
#endif
     /* Mark end with ANY. */
     IMAGE_TLV_ANY,
};
#endif

/*
 * Verify the integrity of the image.
 * Return non-zero if image could not be validated/does not validate.
 */
fih_ret
bootutil_img_validate(struct enc_key_data *enc_state, int image_index,
                      struct image_header *hdr, const struct flash_area *fap,
                      uint8_t *tmp_buf, uint32_t tmp_buf_sz, uint8_t *seed,
                      int seed_len, uint8_t *out_hash)
{
    uint32_t off;
    uint16_t len;
    uint16_t type;
    int image_hash_valid = 0;
#ifdef EXPECTED_SIG_TLV
    FIH_DECLARE(valid_signature, FIH_FAILURE);
#ifndef MCUBOOT_BUILTIN_KEY
    int key_id = -1;
#else
    /* Pass a key ID equal to the image index, the underlying crypto library
     * is responsible for mapping the image index to a builtin key ID.
     */
    int key_id = image_index;
#endif /* !MCUBOOT_BUILTIN_KEY */
#ifdef MCUBOOT_HW_KEY
    uint8_t key_buf[KEY_BUF_SIZE];
#endif
#endif /* EXPECTED_SIG_TLV */
    struct image_tlv_iter it;
    uint8_t buf[SIG_BUF_SIZE];
    uint8_t hash[IMAGE_HASH_SIZE];
#ifdef MCUBOOT_USE_HASH_REF
    uint8_t hash_ref[IMAGE_HASH_SIZE];
#endif /* MCUBOOT_USE_HASH_REF */
    int rc = 0;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
#ifdef MCUBOOT_HW_ROLLBACK_PROT
    fih_int security_cnt = fih_int_encode(INT_MAX);
    uint32_t img_security_cnt = 0;
    FIH_DECLARE(security_counter_valid, FIH_FAILURE);
#endif
    /* Variables to verify unicity of Unprotected TLV types */
    uint32_t tlv_enc = 0;
    uint32_t tlv_sig = 0;
    uint32_t tlv_key = 0;
    uint32_t tlv_hash = 0;

    rc = bootutil_img_hash(enc_state, image_index, hdr, fap, tmp_buf,
            tmp_buf_sz, hash, seed, seed_len);
    if (rc) {
        goto out;
    }

    if (out_hash) {
        memcpy(out_hash, hash, IMAGE_HASH_SIZE);
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, IMAGE_TLV_ANY, false);
    if (rc) {
        goto out;
    }

    if (it.tlv_end > bootutil_max_image_size(fap)) {
        rc = -1;
        goto out;
    }

    /*
     * Traverse through all of the TLVs, performing any checks we know
     * and are able to do.
     */
    while (true) {
        rc = bootutil_tlv_iter_next(&it, &off, &len, &type);
        if (rc < 0) {
            goto out;
        } else if (rc > 0) {
            break;
        }

#ifndef ALLOW_ROGUE_TLVS
        /*
         * Ensure that the non-protected TLV only has entries necessary to hold
         * the signature.  We also allow encryption related keys to be in the
         * unprotected area.
         */
        if (!bootutil_tlv_iter_is_prot(&it, off)) {
             bool found = false;
             for (const uint16_t *p = allowed_unprot_tlvs; *p != IMAGE_TLV_ANY; p++) {
                  if (type == *p) {
                       found = true;
                       break;
                  }
             }
             if (!found) {
                  BOOT_LOG_INF("unexpected TLV %x ", type);
                  FIH_SET(fih_rc, FIH_FAILURE);
                  goto out;
             }
        }
#endif

        if (type == EXPECTED_HASH_TLV) {
            /* Check TLV is unique */
            if (tlv_hash != 0) {
                rc = -1;
                goto out;
            }
            tlv_hash++;
            /* Verify the image hash. This must always be present. */
            if (len != sizeof(hash)) {
                rc = -1;
                goto out;
            }
            rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, sizeof(hash));
            if (rc) {
                goto out;
            }

            FIH_CALL(boot_fih_memequal, fih_rc, hash, buf, sizeof(hash));
            if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
                FIH_SET(fih_rc, FIH_FAILURE);
                goto out;
            }

            image_hash_valid = 1;
#ifdef EXPECTED_KEY_TLV
        } else if (type == EXPECTED_KEY_TLV) {
            /* Check TLV is unique */
            if (tlv_key != 0) {
                rc = -1;
                goto out;
            }
            tlv_key++;
            /*
             * Determine which key we should be checking.
             */
#if (EXPECTED_KEY_TLV == IMAGE_TLV_KEYHASH)
            if (len != IMAGE_HASH_SIZE) {
#elif (EXPECTED_KEY_TLV == IMAGE_TLV_PUBKEY)
            if (len != EXPECTED_PUBKEY_LEN) {
#else
#error "EXPECTED_KEY_TLV not supported"
#endif
                rc = -1;
                goto out;
            }
#ifndef MCUBOOT_HW_KEY
            rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, len);
            if (rc) {
                goto out;
            }
            key_id = bootutil_find_key(image_index, buf, len);
#else
            rc = LOAD_IMAGE_DATA(hdr, fap, off, key_buf, len);
            if (rc) {
                goto out;
            }
            key_id = bootutil_find_key(image_index, key_buf, len);
#endif /* !MCUBOOT_HW_KEY */
            /* The key must be found */
            if (key_id < 0 || key_id >= bootutil_key_cnt) {
                rc = -1;
                goto out;
            }
#endif /* EXPECTED_KEY_TLV */
#ifdef EXPECTED_SIG_TLV
        } else if (type == EXPECTED_SIG_TLV) {
            /* Exit if signature is already verified */
            if (FIH_NOT_EQ(valid_signature, FIH_FAILURE)) {
                rc = -1;
                goto out;
            }

            /* Check TLV is unique */
            if (tlv_sig != 0) {
                rc = -1;
                goto out;
            }
            tlv_sig++;
            /* Check signature lenght */
            if (!EXPECTED_SIG_LEN(len) || len > sizeof(buf)) {
                rc = -1;
                goto out;
            }
#if defined(MCUBOOT_USE_HASH_REF)
             /** Signature verification for authentication is done for:
              *  - SECONDARY slots
              *  - PRIMARY slots on the first signature verification at first boot
              *  For subsequent boots, authentication (of PRIMARY slots) is controlled through a hash saved as a reference
              **/
            if ((ImageValidEnable == 1) && (fap->fa_id == FLASH_AREA_IMAGE_PRIMARY(image_index))) {
                /*
                 * Compare hash of image with reference hash.
                 * If matching, the signature verification can be bypassed.
                 */
                rc = boot_hash_ref_get(hash_ref, sizeof(hash_ref), image_index);
                if (rc == 0) {
                    FIH_CALL(boot_fih_memequal, valid_signature, hash, hash_ref, sizeof(hash));
                    if (FIH_EQ(valid_signature, FIH_SUCCESS)) {
                        BOOT_LOG_INF("Image index: %d, ref hash OK", image_index);

#if defined(MCUBOOT_DOUBLE_SIGN_VERIF)
                        /* Double the reference hash verification (using another way) to resist to basic HW attacks.
                         * The second verification is applicable to final reference hash check on primary slot images
                         * only (condition: ImageValidEnable).
                         * It is performed in 2 steps:
                         * 1- save reference hash verification status in global variable ImageValidStatus[]
                         * 2- verify saved reference hash verification status later in boot process
                         */

                        /* Check ImageValidIndex is in expected range MCUBOOT_IMAGE_NUMBER */
                        if (ImageValidIndex >= MCUBOOT_IMAGE_NUMBER) {
                            rc = -1;
                            goto out;
                        }

                        FIH_CALL(boot_fih_memequal, fih_rc, hash, hash_ref, sizeof(hash));
                        if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
                            ImageValidStatus[ImageValidIndex++] = IMAGE_VALID;
                        }
#endif /* MCUBOOT_DOUBLE_SIGN_VERIF */

                        /* Bypass signature verification */
                        continue;
                    }
                }
            }
#endif /* MCUBOOT_USE_HASH_REF */

            /* Exit if signature is out of bounds. */
            if (key_id < 0 || key_id >= bootutil_key_cnt) {
                rc = -1;
                goto out;
            }
            rc = LOAD_IMAGE_DATA(hdr, fap, off, buf, len);
            if (rc) {
                goto out;
            }
            ImageValidIndex = image_index;
            FIH_CALL(bootutil_verify_sig, valid_signature, hash, sizeof(hash),
                                                           buf, len, key_id);
            BOOT_LOG_INF("Image index: %d, signature %s", image_index,
                         FIH_EQ(valid_signature,FIH_SUCCESS) ? "OK" : "KO");
            key_id = -1;

#if defined(MCUBOOT_USE_HASH_REF)
            if ((ImageValidEnable == 1) && (fap->fa_id == FLASH_AREA_IMAGE_PRIMARY(image_index))) {
                /* Prepare reference hash for next boot, only for images in primary slots. The storage of the
                   reference will be performed later in boot process after double
                   verification. */
                rc = boot_hash_ref_set(hash, sizeof(hash), image_index);
                if (rc) {
                    goto out;
                }
            }
#endif /* MCUBOOT_USE_HASH_REF */
#endif /* EXPECTED_SIG_TLV */
#ifdef MCUBOOT_HW_ROLLBACK_PROT
        } else if (type == IMAGE_TLV_SEC_CNT) {
            /*
             * Verify the image's security counter.
             * This must always be present.
             */
            if (len != sizeof(img_security_cnt)) {
                /* Security counter is not valid. */
                rc = -1;
                goto out;
            }

            rc = LOAD_IMAGE_DATA(hdr, fap, off, &img_security_cnt, len);
            if (rc) {
                goto out;
            }

            FIH_CALL(boot_nv_security_counter_get, fih_rc, image_index,
                                                           &security_cnt);
            if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
                FIH_SET(fih_rc, FIH_FAILURE);
                goto out;
            }

            BOOT_LOG_INF("Verify security counter %d %x %x", image_index, (unsigned int)img_security_cnt, security_cnt.val );

            /* Compare the new image's security counter value against the
             * stored security counter value.
             */
            fih_rc = fih_ret_encode_zero_equality(img_security_cnt <
                                   (uint32_t)fih_int_decode(security_cnt));
            if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
                FIH_SET(fih_rc, FIH_FAILURE);
                goto out;
            }

            /* The image's security counter has been successfully verified. */
            security_counter_valid = fih_rc;
#endif /* MCUBOOT_HW_ROLLBACK_PROT */
#if defined(MCUBOOT_ENCRYPT_EC256)
        } else if (type == IMAGE_TLV_ENC_EC256) {
            /* Check TLV is unique */
            if ((tlv_enc != 0) ||
#if !defined(MCUBOOT_PRIMARY_ONLY)
                /* Check image is encrypted */
                (!IS_ENCRYPTED(hdr)) ||
#endif /* !defined(MCUBOOT_PRIMARY_ONLY) */
                /* Check TLV lenght */
                (len != BOOT_ENC_TLV_SIZE)) {
                rc = -1;
                goto out;
            }
            tlv_enc++;
#endif
        }
    }

    rc = !image_hash_valid;
    if (rc) {
        goto out;
    }

    /** Check that all required unprotected TLVs has been found in the image TLVs and only once
     * exception on the tlv_enc which is only recommended
     **/
    if ((tlv_enc > 1) || (tlv_sig != 1) || (tlv_key != 1) || (tlv_hash != 1)) {
        rc = -1;
        goto out;
    }

#ifdef EXPECTED_SIG_TLV
    FIH_SET(fih_rc, valid_signature);
#endif
#ifdef MCUBOOT_HW_ROLLBACK_PROT
    if (FIH_NOT_EQ(security_counter_valid, FIH_SUCCESS)) {
        rc = -1;
        goto out;
    }
#endif

#if defined(MCUBOOT_ROM_FIXED)
    /* Check if the image is flagged as ROM_FIXED */
    if (!(hdr->ih_flags & IMAGE_F_ROM_FIXED)) {
        rc = -1;
        goto out;
    }

    /* Check if the candidate primary slot corresponds to the primary slot of the current image */
    if (FLASH_AREA_IMAGE_PRIMARY(image_index) != FLASH_AREA_PRIMARY_ROM_FIXED(hdr->ih_load_addr)) {
       rc = -1;
       goto out;
    }
#endif /* defined(MCUBOOT_ROM_FIXED) */


    /* Check pattern in slot, after image payload */
#if !defined(MCUBOOT_PRIMARY_ONLY)
    if (fap->fa_id == FLASH_AREA_IMAGE_SECONDARY(image_index)) {
        off = it.tlv_end;
       /* Check that tlv_end is not overlapping trailer */
        if (off > boot_status_off(fap)) {
            rc = -1;
            goto out;
        }

        /* read flash per byte, until next doubleword */
        if (off % 8) {
            uint32_t end0 = (((off / 8) + 1) * 8);
            while (off < end0) {
                uint8_t data8;
                rc = flash_area_read(fap, off, &data8, sizeof(data8));
                if (rc) {
                    BOOT_LOG_INF("read failed %x ", (unsigned int)off);
                    rc = -1;
                    goto out;
                }
                if (data8 != FLASH_ERASED_BYTE_VAL) {
                    BOOT_LOG_INF("data wrong at %x", (unsigned int)off);
                    rc = -1;
                    goto out;
                }
                off += sizeof(data8);
            }
        }
        /* read flash per doubleword */
#if defined(MCUBOOT_OVERWRITE_ONLY)
        /* check pattern till magic at end of slot */
        uint32_t end = boot_magic_off(fap);
#else
        /* check pattern till trailer */
        uint32_t end = boot_status_off(fap);
#endif /* MCUBOOT_OVERWRITE_ONLY */
        while (off < end) {
            uint64_t data64;
            rc = flash_area_read(fap, off, &data64, sizeof(data64));
            if (rc) {
                BOOT_LOG_INF("read failed %x ", (unsigned int)off);
                rc = -1;
                goto out;
            }
            if (data64 != FLASH_ERASED_DOUBLEWORD_VAL) {
                BOOT_LOG_INF("data wrong at %x", (unsigned int)off);
                rc = -1;
                goto out;
            }
            off += sizeof(data64);
        }
    }
#endif /* !defined(MCUBOOT_PRIMARY_ONLY) */

out:
    if (rc) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

    FIH_RET(fih_rc);
}
