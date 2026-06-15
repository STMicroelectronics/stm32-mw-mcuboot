# origin-pack: STMicroelectronics::mcuboot@2.0.1
# file-format: 1.0.0
project(STMicroelectronics_mcuboot_2_0_1)
cmake_minimum_required(VERSION 3.30)
add_library(STMicroelectronics_mcuboot_2_0_1 INTERFACE)

# List of all CMSIS properties that influence conditions for this package
if(NOT DEFINED CMSIS_Dname)
  set(CMSIS_Dname "CMSIS_Dname not set")
  message(DEBUG "CMSIS_Dname is not set to any value")
endif()

if(NOT DEFINED CMSIS_Dvendor)
  set(CMSIS_Dvendor "CMSIS_Dvendor not set")
  message(DEBUG "CMSIS_Dvendor is not set to any value")
endif()


# Device specific defined symbols




# Include Pre_Include_Global.h globally if needed
if(CMSIS_Tcompiler STREQUAL "IAR")
    target_compile_options(STMicroelectronics_mcuboot_2_0_1 INTERFACE "SHELL:--preinclude $<QUOTE>${CMAKE_CURRENT_LIST_DIR}/Pre_Include_Global.h$<QUOTE>")
else()
    target_compile_options(STMicroelectronics_mcuboot_2_0_1 INTERFACE "SHELL:-include $<QUOTE>${CMAKE_CURRENT_LIST_DIR}/Pre_Include_Global.h$<QUOTE>")
endif()



# Enable all components in this package
if(CMSIS_ENTIRE_STMicroelectronics_mcuboot_2_0_1)
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:MCUboot#Csub:Core#Cversion:1.0.1")
  list(APPEND CMSIS_COMPONENTS_LIST "Cvendor:STMicroelectronics#Cclass:Security#Cgroup:MCUboot#Csub:Platform Common#Cversion:1.0.1")
endif()

# All conditions used by this package

# condition: STMicroelectronics.mcuboot.2.0.1
# description: 
if((CMSIS_Dname MATCHES "STM32.*" AND CMSIS_Dvendor STREQUAL "STMicroelectronics:13"))
  set(STMicroelectronics.mcuboot.2.0.1 "1")
  message(DEBUG "CMSIS condition STMicroelectronics.mcuboot.2.0.1 enabled")
else()
  set(STMicroelectronics.mcuboot.2.0.1 0)
endif()


# condition: STMicroelectronics.mcuboot.2.0.1:MCUboot Platform Common Condition
# description: Ensure Platform Common was selected before
set(STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition "$<NOT:$<STREQUAL:$<FILTER:${CMSIS_COMPONENTS_LIST},INCLUDE,.*Cclass:Security#.*Cgroup:MCUboot#.*Csub:Platform Common(#.*|$)>,>>")
message(DEBUG "CMSIS condition STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition enabled")

# Files and components in this package
if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:MCUboot#Csub:Core#Cversion:1.0.1" IN_LIST CMSIS_COMPONENTS_LIST)  # MCUboot Core component
  message(DEBUG "Using component Security_MCUboot_Core_1_0_1")
  target_compile_definitions(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:-DCMSIS_USE_Security_MCUboot_Core_1_0_1=1>")
  target_include_directories(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/include/>")
  target_include_directories(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/include/bootutil>")
  target_include_directories(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/include/bootutil/crypto>")
  target_include_directories(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/boot_record.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/bootutil_misc.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/bootutil_public.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/caps.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/encrypted.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/fault_injection_hardening.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/fault_injection_hardening_delay_rng_mbedtls.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/image_ecdsa.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/image_ed25519.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/image_validate.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/loader.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/swap_misc.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/swap_move.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/swap_priv.h>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/swap_scratch.c>")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "$<${STMicroelectronics.mcuboot.2.0.1_MCUboot_Platform_Common_Condition}:${CMAKE_CURRENT_LIST_DIR}/boot/bootutil/src/tlv.c>")
endif()

if("Cvendor:STMicroelectronics#Cclass:Security#Cgroup:MCUboot#Csub:Platform Common#Cversion:1.0.1" IN_LIST CMSIS_COMPONENTS_LIST)  # MCUboot Platform Common component
  message(DEBUG "Using component Security_MCUboot_Platform_Common_1_0_1")
  target_compile_definitions(STMicroelectronics_mcuboot_2_0_1 INTERFACE "-DCMSIS_USE_Security_MCUboot_Platform_Common_1_0_1=1")
  target_include_directories(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common/flash_map.c")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common/flash_map_extended.c")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common/flash_map_legacy.c")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common/main.c")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common/security_cnt.c")
  target_sources(STMicroelectronics_mcuboot_2_0_1 INTERFACE "${CMAKE_CURRENT_LIST_DIR}/platform_common/shared_data.c")
endif()

