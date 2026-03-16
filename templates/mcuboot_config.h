/**
  * Copyright (c) 2018 Open Source Foundries Limited
  * Copyright (c) 2019 Arm Limited
  *
  * Copyright (c) 2025 STMicroelectronics.
  *
  * SPDX-License-Identifier: Apache-2.0
  */

#ifndef MCUBOOT_CONF_H
#define MCUBOOT_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Cryptography
 */
/* Supported crypto schemes (do not change values, as used in appli postbuild script) */
#define CRYPTO_SCHEME_EC384      0x1 /* ECDSA-384 signature,
                                        AES-CTR-256 encryption with sym key ECIES-P256 encrypted */
#define CRYPTO_SCHEME_EC256      0x2 /* ECDSA-256 signature,
                                        AES-CTR-128 encryption with sym key ECIES-P256 encrypted */

/* Crypto scheme configuration */
#define CRYPTO_SCHEME            CRYPTO_SCHEME_EC384

/* Crypto scheme settings */
#if (CRYPTO_SCHEME == CRYPTO_SCHEME_EC256)
#define NUM_ECC_BYTES 32
#define MCUBOOT_SIGN_EC256
#define MCUBOOT_ENCRYPT_EC256
#elif (CRYPTO_SCHEME == CRYPTO_SCHEME_EC384)
#define MCUBOOT_SIGN_EC384
#define MCUBOOT_ENCRYPT_EC256
#define MCUBOOT_AES_256
#define MCUBOOT_USE_PSA_CRYPTO
#endif /* CRYPTO_SCHEME */

/* Available crypto implementation */
#define CRYPTO_IMPLEMENTATION_HW 0x1  /* HW crypto through direct HAL */
#define CRYPTO_IMPLEMENTATION_SW 0x2  /* SW crypto through MbedTLS */

/* Crypto implementation configuration */
#define CRYPTO_IMPLEMENTATION    CRYPTO_IMPLEMENTATION_SW

/* Crypto implementation settings */
#if (CRYPTO_IMPLEMENTATION == CRYPTO_IMPLEMENTATION_HW)
#define MCUBOOT_USE_HAL
#define PKA_ECDSA_SIGNATURE_ADDRESS 0x0578UL
#elif (CRYPTO_IMPLEMENTATION == CRYPTO_IMPLEMENTATION_SW)
#define MCUBOOT_USE_MBED_TLS
#endif /* CRYPTO_IMPLEMENTATION */


/*
 * General config
 */
/* Image is revalidated in primary slot after installation */
#define MCUBOOT_VALIDATE_PRIMARY_SLOT

/* Flash having the same sector size can use this flag */
#define MCUBOOT_FLASH_HOMOGENOUS

/* Newer flash map api used */
#define MCUBOOT_USE_FLASH_AREA_GET_SECTORS

/* Use image hash reference to reduce boot time (signature check bypass) */
#define MCUBOOT_USE_HASH_REF

/* Version antirollback counters */
#define MCUBOOT_HW_ROLLBACK_PROT

/* Image encryption supported */
#define MCUBOOT_ENC_IMAGES

/* Flash programmation size granularity (in bytes) */
#define MCUBOOT_BOOT_MAX_ALIGN   16

/* Images measurements (boot record) saved in shared data for next stage */
/* #define MCUBOOT_MEASURED_BOOT */
/* #define MAX_BOOT_RECORD_SZ 0x80 */

/* Additional data saved in shared data for TFM next stage */
/* #define MCUBOOT_DATA_SHARING */
/* #define TFM_PARTITION_FIRMWARE_UPDATE */

/* Hash of public key provisioned */
#define MCUBOOT_HW_KEY

/* Raw private key provisioned */
#define MCUBOOT_RAW_ENC_KEY

/* Targeted primary slot identified in images */
#define MCUBOOT_ROM_FIXED

/*
 * FIH profile
 */
#define MCUBOOT_FIH_PROFILE_HIGH

/*
 * Logging
 */
#ifdef OEMIROT_DEV_MODE
#define MCUBOOT_HAVE_LOGGING
#endif /* OEMIROT_DEV_MODE */

/*
 * Watchdog feeding
 */
#define MCUBOOT_WATCHDOG_FEED()  \
  do {                           \
    /* Do nothing. */            \
  } while (0)

/*
 * Installation mode configuration
 */
#define OVERWRITE_MODE                        0
#define SWAP_MODE                             1
#define INSTALLATION_MODE                     OVERWRITE_MODE /* Select OVERWRITE_MODE or SWAP_MODE */

/* Check installation mode configuration */
#if (INSTALLATION_MODE == OVERWRITE_MODE)
#define MCUBOOT_OVERWRITE_ONLY
#elif (INSTALLATION_MODE == SWAP_MODE)
#define MCUBOOT_SWAP_USING_MOVE
#else
#error "Installation mode configuration error"
#endif /* INSTALLATION_MODE */

/*
 * Application image number:
 * - 1: without isolation
 * - 2: with isolation (S and NS app images)
 */
#define MCUBOOT_APP_IMAGE_NUMBER              1

/*
 * If application
 * - without isolation: Data image number (0 or 1)
 * - with isolation: Secure Data image number (0 or 1)
 */
#define MCUBOOT_S_DATA_IMAGE_NUMBER           0

/*
 * If application
 * - without isolation: 0
 * - with isolation: NonSecure Data image number (0 or 1)
 */
#define MCUBOOT_NS_DATA_IMAGE_NUMBER          0

/* Required definition for project without isolation */
#define MCUBOOT_DATA_IMAGE_NUMBER MCUBOOT_S_DATA_IMAGE_NUMBER

/*
 * Total number of images
 */
#define MCUBOOT_IMAGE_NUMBER (MCUBOOT_APP_IMAGE_NUMBER + MCUBOOT_S_DATA_IMAGE_NUMBER + MCUBOOT_NS_DATA_IMAGE_NUMBER)

/*
 * Inclusion of HAL dependencies
 */
#include "mx_hal_def.h"

#ifdef __cplusplus
}
#endif

#endif /* MCUBOOT_CONF_H */
