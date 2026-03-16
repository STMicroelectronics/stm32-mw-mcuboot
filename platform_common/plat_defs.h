/*
 * Copyright (c) 2017-2022, Arm Limited. All rights reserved.
 * Copyright (c) 2026 STMicroelectronics
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef PLAT_DEFS_H
#define PLAT_DEFS_H
/**
 * \note The interfaces defined in this file must be implemented for each
 *       target.
 */
#include <stdint.h>
#include <limits.h>
enum plat_err_t {
    PLAT_ERR_SUCCESS = 0,
    PLAT_ERR_SYSTEM_ERR = 0x3A5C,
    PLAT_ERR_MAX_VALUE = 0x55A3,
    PLAT_ERR_INVALID_INPUT = 0xA3C5,
    PLAT_ERR_UNSUPPORTED = 0xC35A,
    PLAT_ERR_NOT_PERMITTED = 0xC5A3,
    /* Following entry is only to ensure the error code of int size */
    PLAT_ERR_FORCE_INT_SIZE = INT_MAX
};
#endif /* PLAT_DEFS_H */
