/*
 * Copyright (c) 2019-2020, Arm Limited. All rights reserved.
 * Copyright (c) 2023-2026 STMicroelectronics
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "bootutil/security_cnt.h"
#include "plat_nv_counters.h"
#include "plat_defs.h"
#include "bootutil/fault_injection_hardening.h"
#include <stdint.h>

static enum nv_counter_t get_nv_counter_from_image_id(uint32_t image_id)
{
    uint32_t nv_counter;

    nv_counter = BOOT_NV_COUNTER_0 + image_id;

    /* Check the existence of the enumerated counter value */
    if (nv_counter >= BOOT_NV_COUNTER_MAX) {
        return BOOT_NV_COUNTER_MAX;
    }

    return (enum nv_counter_t)nv_counter;
}

fih_ret boot_nv_security_counter_init(void)
{
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    fih_rc = fih_ret_encode_zero_equality(plat_init_nv_counter());

    FIH_RET(fih_rc);
}

fih_ret boot_nv_security_counter_get(uint32_t image_id, fih_int *security_cnt)
{
    enum nv_counter_t nv_counter;
    FIH_DECLARE(fih_rc, FIH_FAILURE);
    uint32_t security_cnt_soft;

    /* Check if it's a null-pointer. */
    if (!security_cnt) {
        FIH_RET(FIH_FAILURE);
    }

    nv_counter = get_nv_counter_from_image_id(image_id);
    if (nv_counter >= BOOT_NV_COUNTER_MAX) {
        FIH_RET(FIH_FAILURE);
    }

    fih_rc = fih_ret_encode_zero_equality(
             plat_read_nv_counter(nv_counter,
                                  sizeof(security_cnt_soft),
                                  &security_cnt_soft));
    *security_cnt = fih_int_encode(security_cnt_soft);

    FIH_RET(fih_rc);
}

int32_t boot_nv_security_counter_update(uint32_t image_id,
                                        uint32_t img_security_cnt,
                                        uint32_t *updated)
{
    enum nv_counter_t nv_counter;
    enum plat_err_t err;

    nv_counter = get_nv_counter_from_image_id(image_id);
    if (nv_counter >= BOOT_NV_COUNTER_MAX) {
        return -1;
    }

    err = plat_set_nv_counter(nv_counter, img_security_cnt, updated);
    if (err != PLAT_ERR_SUCCESS) {
        return -1;
    }

    return 0;
}
