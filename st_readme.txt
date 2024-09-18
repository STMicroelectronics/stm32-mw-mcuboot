  @verbatim
  ******************************************************************************
  *
  *         Portions COPYRIGHT 2016-2020 STMicroelectronics, All Rights Reserved
  *         Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
  *
  * @file    st_readme.txt 
  * @author  MCD Application Team
  * @brief   This file lists the main modification done by STMicroelectronics on
  *          mcuboot for integration with STM32Cube solution.
  ******************************************************************************
  *
  * original licensing conditions
  * as issued by SPDX-License-Identifier: Apache-2.0
  *
  ******************************************************************************
  @endverbatim

### 5-Jan-2024 ###
==========================
    + improve control of TLVs

### 25-August-2020 ###
==========================
    + imgtool: imgtool.exe is signed ST

### 23-June-2020 ###
==========================
    + imgtool: Cryptodome python module not required
    + imgtool: numpy python module added in requirements.txt

### 12-June-2020 ###
==========================
    + fix start offset of code injection check in padding area

### 11-June-2020 ###
==========================
    + fix to accept TLV DEPENDENCY in during TLV verification

### 02-June-2020 ###
==========================
    + mcuboot release v1.5.0
    + adaptation for BL2
    + imgtool: add flash and ass commands
    + imgtool: add otfdec support and primary-only image support
    + code adaptation for otfdec
    + fix don't check secure image with non secure key
    + fix for MCUBOOT_IMAGE_NUMBER = 1
    + Introduce switch to allow double signature check with single signature computation.
    + fix code injection in padding area.
    + fix compile warnings