/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 * Copyright (c) 2017-2020 Arm Limited.
 * Copyright (c) 2023-2026 STMicroelectronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mcuboot_config.h"
#include <assert.h>
#include "mbedtls/memory_buffer_alloc.h"
#include "bootutil/security_cnt.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/image.h"
#include "bootutil/bootutil.h"
#include "bootutil/boot_record.h"
#include "bootutil/fault_injection_hardening.h"
#include "flash_map_backend.h"
#include "boot_hal.h"
#include "boot_hal_cfg.h"

#if defined(MCUBOOT_USE_PSA_CRYPTO)
#include "psa/crypto.h"
/* A few macros for stringification */
#define str(X) #X
#define xstr(X) str(X)
#endif /* MCUBOOT_USE_PSA_CRYPTO */

/* Avoids the semihosting issue */
#if defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
__asm("  .global __ARM_use_no_argv\n");
#endif

/* Allow to be customized by the project else the default value is applied */
#if !defined(ROT_MBEDTLS_MEM_BUF_LEN)
#ifdef MCUBOOT_ENCRYPT_RSA
#define ROT_MBEDTLS_MEM_BUF_LEN 0x2500
#else
#define ROT_MBEDTLS_MEM_BUF_LEN 0x2000
#endif /* MCUBOOT_ENCRYPT_RSA */
#endif /* !ROT_MBEDTLS_MEM_BUF_LEN */

/* Static buffer to be used by mbedtls for memory allocation */
#ifdef __ICCARM__
__NO_INIT static uint8_t mbedtls_mem_buf[ROT_MBEDTLS_MEM_BUF_LEN];
#else
static uint8_t mbedtls_mem_buf[ROT_MBEDTLS_MEM_BUF_LEN] __attribute__((section(".bss.NoInit"))) ;
#endif /* __ICCARM__ */

static void do_boot(struct boot_rsp *rsp)
{
    struct boot_arm_vector_table *vt;
    uintptr_t flash_base;
    int rc;

    /* The beginning of the image is the ARM vector table, containing
     * the initial stack pointer address and the reset vector
     * consecutively. Manually set the stack pointer and jump into the
     * reset vector
     */
    rc = flash_device_base(rsp->br_flash_dev_id, &flash_base);
    (void)rc;
    assert(rc == 0);

#if defined (MCUBOOT_RAM_LOAD)
    if (rsp->br_hdr->ih_flags & IMAGE_F_RAM_LOAD) {
       /* The image has been copied to SRAM, find the vector table
        * at the load address instead of image's address in flash
        */
        vt = (struct boot_arm_vector_table *)(rsp->br_hdr->ih_load_addr +
                                         rsp->br_hdr->ih_hdr_size);
#else
    if (0){
#endif /* (MCUBOOT_RAM_LOAD) */
    } else {
        /* Using the flash address as not executing in SRAM */
        vt = (struct boot_arm_vector_table *)(flash_base + rsp->br_image_off + rsp->br_hdr->ih_hdr_size);
    }

    /* This function never returns, because it calls the secure application
     * Reset_Handler().
     */
    boot_platform_quit(vt);
}

int main(void)
{
    struct boot_rsp rsp;
    fih_ret fih_rc = FIH_FAILURE;
#if defined(OEMIROT_FAST_WAKE_UP)
    struct boot_arm_vector_table *vt = NULL;
#endif /* OEMIROT_FAST_WAKE_UP */

    /* Perform platform specific initialization */
    if (boot_platform_init() != 0) {
        BOOT_LOG_ERR("Platform init failed");
        FIH_PANIC;
    }

#if defined(OEMIROT_FAST_WAKE_UP)
    FIH_CALL(boot_platform_wakeup, fih_rc);
    if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
        FIH_CALL(boot_platform_vector_table, fih_rc, &vt);
        if (FIH_EQ(fih_rc, FIH_SUCCESS)) {
            BOOT_LOG_INF("Fast wake-up from low-power mode");
            boot_platform_quit(vt);
        }
    }
#endif /* OEMIROT_FAST_WAKE_UP */

    /* Initialise the mbedtls static memory allocator so that mbedtls allocates
     * memory from the provided static buffer instead of from the heap.
     */
    mbedtls_memory_buffer_alloc_init(mbedtls_mem_buf, ROT_MBEDTLS_MEM_BUF_LEN);

    FIH_CALL(boot_nv_security_counter_init, fih_rc);
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        BOOT_LOG_ERR("Error while initializing the security counter");
        FIH_PANIC;
    }

#if defined(MCUBOOT_USE_PSA_CRYPTO)
    /* If the bootloader is configured to use PSA Crypto APIs in the
     * abstraction layer, the component needs to be explicitly initialized
     * before MCUboot APIs, as the crypto abstraction expects that the init
     * has already happened
     */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        BOOT_LOG_ERR("PSA Crypto init failed with error code %d", status);
        FIH_PANIC;
    }
    BOOT_LOG_INF("PSA Crypto init done, sig_type: %s", xstr(MCUBOOT_SIGNATURE_TYPE));
#endif /* MCUBOOT_USE_PSA_CRYPTO */

    FIH_CALL(boot_go, fih_rc, &rsp);
    if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
        BOOT_LOG_ERR("Unable to find bootable image");
#if defined(MCUBOOT_EXT_LOADER)
        boot_platform_noimage();
#else
        FIH_PANIC;
#endif /* MCUBOOT_EXT_LOADER */
    }

    BOOT_LOG_INF("Jumping to the first image slot at address offset: 0x%x",
                 (int)rsp.br_image_off);
    do_boot(&rsp);

    BOOT_LOG_ERR("Never should get here");
    FIH_PANIC;
}
