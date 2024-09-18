# [mcuboot](http://mcuboot.com/)

![latest tag](https://img.shields.io/github/v/tag/STMicroelectronics/stm32-mw-mcuboot.svg?color=brightgreen)

This is mcuboot version 1.5.0

MCUboot is a secure bootloader for 32-bit MCUs. The goal of MCUboot is to
define a common infrastructure for the bootloader, system flash layout on
microcontroller systems, and to provide a secure bootloader that enables
simple software upgrades.

MCUboot is operating system and hardware independent and relies on
hardware porting layers from the operating. Currently, mcuboot works
with both the Apache Mynewt and Zephyr operating systems, but more
ports are planned in the future. RIOT is currently supported as a boot
target with a complete port planned.

## Release note

Details about the updates made by STMicroelectronics are available in the release note [here](https://github.com/STMicroelectronics/stm32-mw-mcuboot/blob/main/st_readme.txt).

## Using MCUboot

Instructions for different operating systems can be found here:
- [Zephyr](docs/readme-zephyr.md)
- [Mynewt](docs/readme-mynewt.md)
- [RIOT](docs/readme-riot.md)

## Roadmap

The issues being planned and worked on are tracked using GitHub issues. To
participate please visit:

[MCUBoot GitHub Issues](https://github.com/JuulLabs-OSS/mcuboot/issues)

~~Issues were previously tracked on [MCUboot JIRA](https://runtimeco.atlassian.net/projects/MCUB/summary)
, but it is now deprecated.~~

## Browsing

Information and documentation on the bootloader are stored within the source.

~~It was previously also documented on confluence:
[MCUBoot Confluence](https://runtimeco.atlassian.net/wiki/discover/all-updates)
however, it is now deprecated and not currently maintained~~

For more information in the source, here are some pointers:

- [boot/bootutil](boot/bootutil): The core of the bootloader itself.
- [boot/boot\_serial](boot/boot_serial): Support for serial upgrade within the bootloader itself.
- [boot/zephyr](boot/zephyr): Port of the bootloader to Zephyr
- [boot/mynewt](boot/mynewt): Mynewt bootloader app
- [imgtool](scripts/imgtool.py): A tool to securely sign firmware images for booting by mcuboot.
- [sim](sim): A bootloader simulator for testing and regression

## Joining

Developers welcome!

* Our developer mailing list:
  https://groups.io/g/mcuboot
* Our Slack channel: https://mcuboot.slack.com/ <br />
  Get your invite [here!](https://join.slack.com/t/mcuboot/shared_invite/MjE2NDcwMTQ2MTYyLTE1MDA4MTIzNTAtYzgyZTU0NjFkMg)
