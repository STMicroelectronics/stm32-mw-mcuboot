#! /usr/bin/env python3
#
# Copyright 2017-2020 Linaro Limited
# Copyright 2019-2024 Arm Limited
# Copyright 2020-2026 STMicroelectronics
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import click
import getpass

import sys
import struct
import os
import lzma
import base64
from struct import pack
from imgtool import image
from imgtool.keys import *
from imgtool import image, imgtool_version
from imgtool.version import decode_version
from imgtool.dumpinfo import dump_imginfo

from imgtool.keys.rsa import *
from imgtool.keys.ecdsa import *
from imgtool.keys.symkey import *
from imgtool.keys.aesgcm import *
from imgtool.keys import (
    RSAUsageError, ECDSAUsageError, Ed25519UsageError, X25519UsageError)

comp_default_dictsize=131072
comp_default_pb=2
comp_default_lc=3
comp_default_lp=1
comp_default_preset=9


MIN_PYTHON_VERSION = (3, 6)
if sys.version_info < MIN_PYTHON_VERSION:
    sys.exit("Python %s.%s or newer is required by imgtool."
             % MIN_PYTHON_VERSION)


def gen_rsa2048(keyfile, passwd, export):
    new_key=RSA.generate()
    new_key.export_private(path=keyfile, passwd=passwd)
    if export:
      new_key.export_public(path=export)

def gen_rsa3072(keyfile, passwd, export):
    new_key=RSA.generate(key_size=3072)
    new_key.export_private(path=keyfile,passwd=passwd)
    if export:
      new_key.export_public(path=export)

def gen_ecdsa_p256(keyfile, passwd, export):
    new_key=ECDSA256P1.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
    if export:
      new_key.export_public(path=export)

def gen_ecdsa_p256_ssl(keyfile, passwd, export):
    new_key=ECDSA256P1_SSL.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
    if export:
      new_key.export_public(path=export)

def gen_ecdsa_p384(keyfile, passwd, export):
    new_key=ECDSA384P1.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
    if export:
      new_key.export_public(path=export)

def gen_sym_32(keyfile, passwd, export):
    new_key=SYMKEY.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
   
def gen_ed25519(keyfile, passwd, export):
    new_key=Ed25519.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
    
def gen_x25519(keyfile, passwd, export):
    new_key=X25519.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
    
def gen_aesgcm(keyfile, passwd, export):
    new_key=AESGCM.generate()
    new_key.export_private(path=keyfile,passwd=passwd)
   

valid_langs = ['c', 'rust']
valid_hash_encodings = ['lang-c', 'raw']
valid_encodings = ['lang-c', 'lang-rust', 'pem', 'raw']
keygens = {
    'rsa-2048':   gen_rsa2048,
    'rsa-3072':   gen_rsa3072,
    'ecdsa-p256': gen_ecdsa_p256,
    'ecdsa-p384': gen_ecdsa_p384,
    'ed25519':    gen_ed25519,
    'x25519':     gen_x25519,
    'ecdsa-p256-ssl': gen_ecdsa_p256_ssl,
    'sym32': gen_sym_32,
    'aesgcm': gen_aesgcm
}
valid_formats = ['openssl', 'pkcs8']
valid_sha = [ 'auto', '256', '384', '512' ]

def get_key_type(public_key_pem):
    try:
        public_key = load_key(public_key_pem)
        if isinstance(public_key, RSAPublic):
            key_size = public_key.key_size
            if key_size == 2048:
                return 'rsa-2048'
            elif key_size == 3072:
                return 'rsa-3072'
            else:
                return f'Unknown RSA key size: {key_size}'
        elif isinstance(public_key, ECDSA256P1Public):
            return 'ecdsa-p256'
        elif isinstance(public_key, ECDSA384P1Public):
            return 'ecdsa-p384'
        elif isinstance(public_key,Ed25519Public):
            return 'ed25519'
        elif isinstance(public_key,X25519Public):
            return 'x25519'
        else:
            return 'Unknown key type'
    except Exception as e:
        return f'Error loading public key: {e}'



def load_signature(sigfile):
    with open(sigfile, 'rb') as f:
        signature = base64.b64decode(f.read())
        return signature


def save_signature(sigfile, sig):
    with open(sigfile, 'wb') as f:
        signature = base64.b64encode(sig)
        f.write(signature)


def load_key(keyfile):
    # TODO: better handling of invalid pass-phrase
    key = load(keyfile)
    if key is not None:
        return key
    passwd = getpass.getpass("Enter key passphrase: ").encode('utf-8')
    return load(keyfile, passwd)


def get_password():
    while True:
        passwd = getpass.getpass("Enter key passphrase: ")
        passwd2 = getpass.getpass("Reenter passphrase: ")
        if passwd == passwd2:
            break
        print("Passwords do not match, try again")

    # Password must be bytes, always use UTF-8 for consistent
    # encoding.
    return passwd.encode('utf-8')


@click.option('-p', '--password', is_flag=True,
              help='Prompt for password to protect key')
@click.option('-t', '--type', metavar='type', required=True,
              type=click.Choice(keygens.keys()), prompt=True,
              help='{}'.format('One of: {}'.format(', '.join(keygens.keys()))))
@click.option('-k', '--key', metavar='filename', required=True)
@click.option('-e', '--export', metavar='filename', required=False)
@click.command(help='Generate pub/private keypair')
def keygen(type, key, password, export):
    password = get_password() if password else None
    keygens[type](key, password, export)


@click.option('-l', '--lang', metavar='lang',
              type=click.Choice(valid_langs),
              help='This option is deprecated. Please use the '
                   '`--encoding` option. '
                   'Valid langs: {}'.format(', '.join(valid_langs)))
@click.option('-e', '--encoding', metavar='encoding',
              type=click.Choice(valid_encodings),
              help='Valid encodings: {}'.format(', '.join(valid_encodings)))
@click.option('-k', '--key', metavar='filename', required=True)
@click.option('-o', '--output', metavar='output', required=False,
              help='Specify the output file\'s name. \
                    The stdout is used if it is not provided.')
@click.command(help='Dump public key from keypair')
def getpub(key, encoding, lang, output):
    if encoding and lang:
        raise click.UsageError('Please use only one of `--encoding/-e` '
                               'or `--lang/-l`')
    elif not encoding and not lang:
        # Preserve old behavior defaulting to `c`. If `lang` is removed,
        # `default=valid_encodings[0]` should be added to `-e` param.
        lang = valid_langs[0]
    key = load_key(key)

    if not output:
        output = sys.stdout
    if key is None:
        print("Invalid passphrase")
    elif lang == 'c' or encoding == 'lang-c':
        key.emit_c_public(file=output)
    elif lang == 'rust' or encoding == 'lang-rust':
        key.emit_rust_public(file=output)
    elif encoding == 'pem':
        key.emit_public_pem(file=output)
    elif encoding == 'raw':
        key.emit_raw_public(file=output)
    else:
        raise click.UsageError()


@click.option('-e', '--encoding', metavar='encoding',
              type=click.Choice(valid_hash_encodings),
              help='Valid encodings: {}. '
                   'Default value is {}.'
                   .format(', '.join(valid_hash_encodings),
                           valid_hash_encodings[0]))
@click.option('-k', '--key', metavar='filename', required=True)
@click.option('-o', '--output', metavar='output', required=False,
              help='Specify the output file\'s name. \
                    The stdout is used if it is not provided.')
@click.command(help='Dump the SHA256 (or sha384 if ECDSA-P384) hash of the public key')
def getpubhash(key, output, encoding):
    if not encoding:
        encoding = valid_hash_encodings[0]
    key = load_key(key)

    if not output:
        output = sys.stdout
    if key is None:
        print("Invalid passphrase")
    elif encoding == 'lang-c':
        key.emit_c_public_hash(file=output)
    elif encoding == 'raw':
        key.emit_raw_public_hash(file=output)
    else:
        raise click.UsageError()


@click.option('--minimal', default=False, is_flag=True,
              help='Reduce the size of the dumped private key to include only '
                   'the minimum amount of data required to decrypt. This '
                   'might require changes to the build config. Check the docs!'
              )
@click.option('-k', '--key', metavar='filename', required=True)
@click.option('-f', '--format',
              type=click.Choice(valid_formats),
              help='Valid formats: {}'.format(', '.join(valid_formats))
              )
@click.option('--raw', default=False, is_flag=True,
              help='dumped private key in mode raw'
              )
@click.command(help='Dump private key from keypair')
def getpriv(key, minimal, format,raw):
    key = load_key(key)
    if key is None:
        print("Invalid passphrase")
    try:
        key.emit_private(minimal, format,raw)
    except (RSAUsageError, ECDSAUsageError, Ed25519UsageError,
            X25519UsageError) as e:
        raise click.UsageError(e)



@click.option('--minimal', default=False, is_flag=True,
              help='Reduce the size of the dumped private key to include only '
                   'the minimum amount of data required to decrypt. This '
                   'might require changes to the build config. Check the docs!'
              )
@click.option('--raw', default=False, is_flag=True,
              help='dumped private key in mode raw'
              )
@click.option('-k', '--key', metavar='filename', required=True)
@click.command(help='Dump private key from keypair, in binary format')
def getprivbin(key, minimal, raw):
    key = load_key(key)
    if key is None:
        print("Invalid passphrase")
    try:
        key.emit_private_bin(minimal, raw)
    except (RSAUsageError, ECDSAUsageError, Ed25519UsageError,
            X25519UsageError) as e:
        raise click.UsageError(e)


@click.option('--sha', default=False, is_flag=True,
              help='Get public sha256 (or sha384 if ECDSA-P384) of public key'
              )
@click.option('--raw', default=False, is_flag=True,
              help='dumped public key in mode raw'
              )
@click.option('-k', '--key', metavar='filename', required=True)
@click.command(help='Dump public key in binary format')
def getpubbin(key, sha, raw):
    key = load_key(key)
    if key is None:
        print("Invalid passphrase")
    try:
        key.emit_public_bin(sha,raw)
    except (RSAUsageError, ECDSAUsageError, Ed25519UsageError,
            X25519UsageError) as e:
        raise click.UsageError(e)


@click.argument('imgfile')
@click.option('-k', '--key', metavar='filename')
@click.command(help="Check that signed image can be verified by given key")
def verify(key, imgfile):
    key = load_key(key) if key else None
    ret, version, digest = image.Image.verify(imgfile, key)
    if ret == image.VerifyResult.OK:
        print("Image was correctly validated")
        print("Image version: {}.{}.{}+{}".format(*version))
        print("Image digest: {}".format(digest.hex()))
        return
    elif ret == image.VerifyResult.INVALID_MAGIC:
        print("Invalid image magic; is this an MCUboot image?")
    elif ret == image.VerifyResult.INVALID_TLV_INFO_MAGIC:
        print("Invalid TLV info magic; is this an MCUboot image?")
    elif ret == image.VerifyResult.INVALID_HASH:
        print("Image has an invalid hash")
    elif ret == image.VerifyResult.INVALID_SIGNATURE:
        print("No signature found for the given key")
    elif ret == image.VerifyResult.KEY_MISMATCH:
        print("Key type does not match TLV record")
    else:
        print("Unknown return code: {}".format(ret))
    sys.exit(1)


@click.argument('imgfile')
@click.option('-o', '--outfile', metavar='filename', required=False,
              help='Save image information to outfile in YAML format')
@click.option('-s', '--silent', default=False, is_flag=True,
              help='Do not print image information to output')
@click.command(help='Print header, TLV area and trailer information '
                    'of a signed image')
def dumpinfo(imgfile, outfile, silent):
    dump_imginfo(imgfile, outfile, silent)
    print("dumpinfo has run successfully")

class BasedIntAllParamType(click.ParamType):
    name = 'integer'

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value
        try:
            if value[:2].lower() == "0x":
                return int(value[2:], 16)
            elif value[:1] == "0":
                return int(value, 8)
            return int(value, 10)
        except ValueError:
            self.fail('%s is not a valid integer. '
                      'prefixed with 0b/0B, 0o/0O, or 0x/0X as necessary.'
                      % value, param, ctx)


def validate_version(ctx, param, value):
    try:
        decode_version(value)
        return value
    except ValueError as e:
        raise click.BadParameter("{}".format(e))


def validate_security_counter(ctx, param, value):
    if value is not None:
        if value.lower() == 'auto':
            return 'auto'
        else:
            try:
                return int(value, 0)
            except ValueError:
                raise click.BadParameter(
                    "{} is not a valid integer. Please use code literals "
                    "prefixed with 0b/0B, 0o/0O, or 0x/0X as necessary."
                    .format(value))


def validate_header_size(ctx, param, value):
    min_hdr_size = image.IMAGE_HEADER_SIZE
    if value < min_hdr_size:
        raise click.BadParameter(
            "Minimum value for -H/--header-size is {}".format(min_hdr_size))
    return value


def get_dependencies(ctx, param, value):
    if value: 
        versions = []
        images = []
        dependencies = dict()
        for dep in value:
            match = re.match(r'^\((\d+),\s*([0-9.]+)\)$', dep) #multiple
            if match:
                image_id, raw_version = match.groups()
                images.append(image_id)
                try:
                    versions.append(decode_version(raw_version))
                except ValueError as e:
                    raise click.BadParameter("{}".format(e))
            else:                                               #one line
                dep_images = re.findall(r"\((\d+)", dep)
                if len(dep_images) == 0:
                    raise click.BadParameter(
                        "Image dependency format is invalid: {}".format(dep))
                raw_versions = re.findall(r",\s*([0-9.]+)\)", dep)
                if len(dep_images) != len(raw_versions):
                    raise click.BadParameter(
                        '''There's a mismatch between the number of dependency images
                        and versions in: {}'''.format(dep))
                for raw_version in raw_versions:
                    try:
                        versions.append(decode_version(raw_version))
                    except ValueError as e:
                        raise click.BadParameter("{}".format(e))
                images.extend(dep_images)
        
        dependencies[image.DEP_IMAGES_KEY] = images
        dependencies[image.DEP_VERSIONS_KEY] = versions
        return dependencies
    else: 
        return None
def create_lzma2_header(dictsize, pb, lc, lp):
    header = bytearray()
    for i in range(0, 40):
        if dictsize <= ((2 | ((i) & 1)) << int((i) / 2 + 11)):
            header.append(i)
            break
    header.append( ( pb * 5 + lp) * 9 + lc)
    return header

class BasedIntParamType(click.ParamType):
    name = 'integer'

    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail('%s is not a valid integer. Please use code literals '
                      'prefixed with 0b/0B, 0o/0O, or 0x/0X as necessary.'
                      % value, param, ctx)


@click.argument('outfile')
@click.argument('infile')
@click.option('--non-bootable', default=False, is_flag=True,
              help='Mark the image as non-bootable.')
@click.option('--custom-tlv', required=False, nargs=2, default=[],
              multiple=True, metavar='[tag] [value]',
              help='Custom TLV that will be placed into protected area. '
                   'Add "0x" prefix if the value should be interpreted as an '
                   'integer, otherwise it will be interpreted as a string. '
                   'Specify the option multiple times to add multiple TLVs.')
@click.option('-R', '--erased-val', type=click.Choice(['0', '0xff']),
              required=False,
              help='The value that is read back from erased flash.')
@click.option('-x', '--hex-addr', type=BasedIntParamType(), required=False,
              help='Adjust address in hex output file.')
@click.option('-L', '--load-addr', type=BasedIntParamType(), required=False,
              help='Load address for image when it should run from RAM.')
@click.option('-F', '--rom-fixed', type=BasedIntParamType(), required=False,
              help='Set flash address the image is built for.')
@click.option('--save-enctlv', default=False, is_flag=True,
              help='When upgrading, save encrypted key TLVs instead of plain '
                   'keys. Enable when BOOT_SWAP_SAVE_ENCTLV config option '
                   'was set.')
@click.option('-E', '--encrypt', metavar='filename',
              help='Encrypt image using the provided public key. '
                   '(Not supported in direct-xip or ram-load mode.)')
@click.option('--encrypt-keylen', default='128',
              type=click.Choice(['128', '256']),
              help='When encrypting the image using AES, select a 128 bit or '
                   '256 bit key len.')
@click.option('--compression', default='disabled',
              type=click.Choice(['disabled', 'lzma2', 'lzma2armthumb']),
              help='Enable image compression using specified type. '
                   'Will fall back without image compression automatically '
                   'if the compression increases the image size.')
@click.option('-c', '--clear', required=False, is_flag=True, default=False,
              help='Output a non-encrypted image with encryption capabilities,'
                   'so it can be installed in the primary slot, and encrypted '
                   'when swapped to the secondary.')
@click.option('-e', '--endian', type=click.Choice(['little', 'big']),
              default='little', help="Select little or big endian")
@click.option('--overwrite-only', default=False, is_flag=True,
              help='Use overwrite-only instead of swap upgrades')
@click.option('--boot-record', metavar='sw_type', help='Create CBOR encoded '
              'boot record TLV. The sw_type represents the role of the '
              'software component (e.g. CoFM for coprocessor firmware). '
              '[max. 12 characters]')
@click.option('-M', '--max-sectors', type=int,
              help='When padding allow for this amount of sectors (defaults '
                   'to 128)')
@click.option('--confirm', default=False, is_flag=True,
              help='When padding the image, mark it as confirmed (implies '
                   '--pad)')
@click.option('--pad', default=False, is_flag=True,
              help='Pad image to --slot-size bytes, adding trailer magic')
@click.option('-S', '--slot-size', type=BasedIntParamType(), required=True,
              help='Size of the slot. If the slots have different sizes, use '
              'the size of the secondary slot.')
@click.option('--pad-header', default=False, is_flag=True,
              help='Add --header-size zeroed bytes at the beginning of the '
                   'image')
@click.option('-H', '--header-size', callback=validate_header_size,
              type=BasedIntParamType(), required=True)
@click.option('-o', '--otfdec',
              type=BasedIntParamType(), required=False)
@click.option('-P','--primary-only',  default=False, is_flag=True,
              help='when encrypted image hash and signature are computed with header '
                    'without encrypted flag')
@click.option('--pad-sig', default=False, is_flag=True,
              help='Add 0-2 bytes of padding to ECDSA signature '
                   '(for mcuboot <1.5)')
@click.option('-d', '--dependencies', callback=get_dependencies, multiple=True,
              required=False, help='''Add dependence on another image, format:
              "(<image_ID>,<image_version>), ... " or multiple "-d (1,1.0.0) -d (2,1.0.0)"''')
@click.option('-s', '--security-counter', callback=validate_security_counter,
              help='Specify the value of security counter. Use the `auto` '
              'keyword to automatically generate it from the image version.')
@click.option('-v', '--version', callback=validate_version,  required=True)
@click.option('--align', type=click.Choice(['1', '2', '4', '8', '16', '32']),
              default='16',
              required=False,
              help='Alignment used by swap update modes.')
@click.option('--max-align', type=click.Choice(['8', '16', '32']),
              required=False,
              help='Maximum flash alignment. Set if flash alignment of the '
              'primary and secondary slot differ and any of them is larger '
              'than 8.')
@click.option('--public-key-format', type=click.Choice(['hash', 'full']),
              default='hash', help='In what format to add the public key to '
              'the image manifest: full key or hash of the key.')
@click.option('-k', '--key', metavar='filename')
@click.option('--fix-sig', metavar='filename',
              help='fixed signature for the image. It will be used instead of '
              'the signature calculated using the public key')
@click.option('--fix-sig-pubkey', metavar='filename',
              help='public key relevant to fixed signature')
@click.option('--sig-out', metavar='filename',
              help='Path to the file to which signature will be written. '
              'The image signature will be encoded as base64 formatted string')
@click.option('--sha', 'user_sha', type=click.Choice(valid_sha), default='auto',
              help='selected sha algorithm to use; defaults to "auto" which is 256 if '
              'no cryptographic signature is used, or default for signature type')
@click.option('--vector-to-sign', type=click.Choice(['payload', 'digest']),
              help='send to OUTFILE the payload or payload''s digest instead '
              'of complied image. These data can be used for external image '
              'signing')
@click.option('-ma', '--magic-val', type=BasedIntAllParamType(), required=False,
              help='fix magic value in hex output file.', default="0x96f3b83d")
@click.option('--no-pad-tlv', is_flag=True, default=False,
              help='disable tlv padding (in case of magic in %s)' % image.Image.STiROTlist())
@click.option('-l','--licence', type=click.Choice(['0', '1']),
              required=False, default='0', help='Fix Licence : 0 (global licence) 1(chip licence)')
@click.command(help='''Create a signed or unsigned image\n
               INFILE and OUTFILE are parsed as Intel HEX if the params have
               .hex extension, otherwise binary format is used''')
def sign(key, public_key_format, align, version, pad_sig, header_size,
         pad_header, slot_size, pad, confirm, max_sectors, overwrite_only,
         endian, encrypt_keylen, encrypt, compression, infile, outfile,
         dependencies, load_addr, hex_addr, erased_val, save_enctlv,
         security_counter, boot_record, custom_tlv, rom_fixed,otfdec, primary_only, max_align,
         clear, fix_sig, fix_sig_pubkey, sig_out, user_sha, vector_to_sign,magic_val,
         non_bootable,no_pad_tlv,licence):

    if confirm:
        # Confirmed but non-padded images don't make much sense, because
        # otherwise there's no trailer area for writing the confirmed status.
        pad = True
    img = image.Image(version=decode_version(version), header_size=header_size,
                      pad_header=pad_header, pad=pad, confirm=confirm,
                      align=int(align), slot_size=slot_size,
                      max_sectors=max_sectors, overwrite_only=overwrite_only,
                      endian=endian, load_addr=load_addr, rom_fixed=rom_fixed,
                      erased_val=erased_val, save_enctlv=save_enctlv,
                      security_counter=security_counter, max_align=max_align,magic_val=magic_val,
                      non_bootable=non_bootable,no_pad_tlv=no_pad_tlv)
    if vector_to_sign is not None and fix_sig_pubkey is None:
         raise click.UsageError("Public key --fix-sig-pubkey must be specified if --vector-to-sign is used") 
    if key and (fix_sig or fix_sig_pubkey):
        raise click.ClickException("Cannot use --key with --fix-sig or --fix-sig-pubkey")
    
    if magic_val==image.STiROT[0] and primary_only:
        raise click.UsageError("primary-only not compatible with this magic value")
    elif magic_val in image.STiROT and otfdec:
        raise click.UsageError("otfdec not compatible with this magic value")
    elif primary_only and otfdec:
        raise click.UsageError("primary-only and otfdec not compatible")
    
    compression_tlvs = {}
    img.load(infile)
    temporary_key = None
    # Generate temporary key to be able to realize padding needed for STiRoT image file
    if(magic_val in image.STiROT) and key is None:
        if fix_sig_pubkey:
            key_type = get_key_type(fix_sig_pubkey)
        temporary_key = "temporary_key.pem"
        keygen_function = keygens[key_type]
        keygen_function(temporary_key,None,None)
        temporary_key = load_key(temporary_key)
        temporary_key.pad_sig = True

    key = load_key(key) if key else None
    enckey = load_key(encrypt) if encrypt else None
    if enckey and key and not (isinstance(enckey, AESGCM)and isinstance(key, ECDSA256P1)):         
        if ((isinstance(key, ECDSA256P1) and
             not isinstance(enckey, ECDSA256P1Public))
           or (isinstance(key, ECDSA384P1) and
               not isinstance(enckey, ECDSA256P1Public))
                or (isinstance(key, RSA) and
                    not isinstance(enckey, RSAPublic))):
            # FIXME
            raise click.UsageError("Signing and encryption must use the same "
                                   "type of key")

    if (pad_sig and hasattr(key, 'pad_sig')) or (key and (magic_val in image.STiROT)):
        key.pad_sig = True

    # Get list of custom protected TLVs from the command-line
    custom_tlvs = {}
    for tlv in custom_tlv:
        tag = int(tlv[0], 0)
        if tag in custom_tlvs:
            raise click.UsageError('Custom TLV %s already exists.' % hex(tag))
        if tag in image.TLV_VALUES.values():
            raise click.UsageError(
                'Custom TLV %s conflicts with predefined TLV.' % hex(tag))

        value = tlv[1]
        if value.startswith('0x'):
            if len(value[2:]) % 2:
                raise click.UsageError('Custom TLV length is odd.')
            custom_tlvs[tag] = bytes.fromhex(value[2:])
        else:
            custom_tlvs[tag] = value.encode('utf-8')

    # Allow signature calculated externally.
    raw_signature = load_signature(fix_sig) if fix_sig else None

    baked_signature = None
    pub_key = None

    if raw_signature is not None or vector_to_sign is not None:
        if fix_sig_pubkey is None:
            raise click.UsageError(
                'public key of the fixed signature is not specified')

        pub_key = load_key(fix_sig_pubkey)

        baked_signature = {
            'value': raw_signature
        }
    img.create(key, public_key_format, enckey, dependencies, boot_record,
               custom_tlvs, compression_tlvs, None, int(encrypt_keylen), clear,
               baked_signature, pub_key, vector_to_sign,user_sha,temporary_key,
               licence=licence,primary_only=primary_only,otfdec=otfdec)
    if compression in ["lzma2", "lzma2armthumb"]:
        compressed_img = image.Image(version=decode_version(version),
                  header_size=header_size, pad_header=pad_header,
                  pad=pad, confirm=confirm, align=int(align),
                  slot_size=slot_size, max_sectors=max_sectors,
                  overwrite_only=overwrite_only, endian=endian,
                  load_addr=load_addr, rom_fixed=rom_fixed,
                  erased_val=erased_val, save_enctlv=save_enctlv,
                  security_counter=security_counter, max_align=max_align)
        compression_filters = [
            {"id": lzma.FILTER_LZMA2, "preset": comp_default_preset,
                "dict_size": comp_default_dictsize, "lp": comp_default_lp,
                "lc": comp_default_lc}
        ]
        if compression == "lzma2armthumb":
            compression_filters.insert(0, {"id":lzma.FILTER_ARMTHUMB})
        compressed_data = lzma.compress(img.get_infile_data(),filters=compression_filters,
            format=lzma.FORMAT_RAW)
        uncompressed_size = len(img.get_infile_data())
        compressed_size = len(compressed_data)
        print(f"compressed image size: {compressed_size} bytes")
        print(f"original image size: {uncompressed_size} bytes")
        compression_tlvs["DECOMP_SIZE"] = struct.pack(
            img.get_struct_endian() + 'L', img.image_size)
        compression_tlvs["DECOMP_SHA"] = img.image_hash
        compression_tlvs_size = len(compression_tlvs["DECOMP_SIZE"])
        compression_tlvs_size += len(compression_tlvs["DECOMP_SHA"])
        if img.get_signature():
            compression_tlvs["DECOMP_SIGNATURE"] = img.get_signature()
            compression_tlvs_size += len(compression_tlvs["DECOMP_SIGNATURE"])
        if (compressed_size + compression_tlvs_size) < uncompressed_size:
            compression_header = create_lzma2_header(
                dictsize = comp_default_dictsize, pb = comp_default_pb,
                lc = comp_default_lc, lp = comp_default_lp)
            compressed_img.load_compressed(compressed_data, compression_header)
            compressed_img.base_addr = img.base_addr
            compressed_img.create(key, public_key_format, enckey,
               dependencies, boot_record, custom_tlvs, compression_tlvs,
               compression, int(encrypt_keylen), clear, baked_signature,
               pub_key, vector_to_sign)
            img = compressed_img
    img.save(outfile, hex_addr)
    if sig_out is not None:
        new_signature = img.get_signature()
        save_signature(sig_out, new_signature)
    if os.path.exists("temporary_key.pem"):
        os.remove("temporary_key.pem")
                

class AliasesGroup(click.Group):

    _aliases = {
        "create": "sign",
    }

    def list_commands(self, ctx):
        cmds = [k for k in self.commands]
        aliases = [k for k in self._aliases]
        return sorted(cmds + aliases)

    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        if cmd_name in self._aliases:
            return click.Group.get_command(self, ctx, self._aliases[cmd_name])
        return None


@click.argument('outfile')
@click.argument('infile')
@click.option('-k', '--key', metavar='filename')
@click.option('--public-key-format', type=click.Choice(['hash', 'full']),
              default='hash', help='In what format to add the public key to '
              'the image manifest: full key or hash of the key.')
@click.option('-x', '--hex-addr', type=BasedIntParamType(), required=False,
              help='Adjust address in hex output file.')
@click.option('--overwrite-only', default=False, is_flag=True,
              help='Use overwrite-only instead of swap upgrades')
@click.option('-e', '--endian', type=click.Choice(['little', 'big']),
              default='little', help="Select little or big endian")
@click.option('--align', type=click.Choice(['1', '2', '4', '8', '16']),
              required=True)
@click.option('--confirm', default=False, is_flag=True,
              help='When padding the image, mark it as confirmed (implies '
                   '--pad)')           
@click.option('--pad', default=False, is_flag=True,
              help='Pad image to --slot-size bytes, adding trailer magic')
@click.option('-R', '--erased-val', type=click.Choice(['0', '0xff']),
              required=False,
              help='The value that is read back from erased flash.')
@click.option('-S', '--slot-size', type=BasedIntParamType(), required=True,
              help='Size of the slot. If the slots have different sizes, use '
              'the size of the secondary slot.')
@click.option('-M', '--max-sectors', type=int,
              help='When padding allow for this amount of sectors (defaults '
                   'to 128)')
@click.option('--save-enctlv', default=False, is_flag=True,
              help='When upgrading, save encrypted key TLVs instead of plain '
                   'keys. Enable when BOOT_SWAP_SAVE_ENCTLV config option '
                   'was set.')              
@click.command(help='''resign a licence image file \n
               INFILE and OUTFILE are parsed as Intel HEX if the params have
               .hex extension, otherwise binary format is used''')
def resign(key, public_key_format, infile, outfile, hex_addr, overwrite_only,
           endian, align, confirm, pad, save_enctlv, erased_val, slot_size, max_sectors):
    key = load_key(key)
    # an image object to save is return
    # if None is return resign is not done
    img = image.Image.resign(infile, key, public_key_format, hex_addr, overwrite_only,endian, 
                                 align, confirm, pad, save_enctlv, erased_val, slot_size, max_sectors)
    if img is not None:
        img.save(outfile, hex_addr)

@click.argument('outfile')
@click.argument('infile')
@click.option('-i', '--input-size', type=BasedIntAllParamType(), required=True,
              help='input padding size')
@click.option('-o', '--optional-size', type=BasedIntAllParamType(), required=False,default='0',
              help='optional padding size')
@click.option('-f', '--file', metavar='filename',default=None,
              help='optional file to place before inputfile and to padd up to --optional-size')
@click.command(help='''Assemble and padd 1 or 2 binaries''')             
def ass(file, input_size, optional_size, infile, outfile ):
    big_binary=b''
    with open(infile, 'rb') as f:
        binary=f.read()
        if input_size != 0:
            binary+=(input_size-len(binary))*pack("B",0xff)
    if file is not None :
        with open(file, 'rb') as f:
            optional_binary=f.read()
    else:
        optional_binary=b''
    if optional_size != 0:
        optional_binary+=(optional_size-len(optional_binary))*pack("B",0xff)
    with open(outfile, 'wb') as f:
       big_binary=optional_binary+binary
       f.write(big_binary) 

@click.option('-i', '--image-num', type=int,default=0,
              help='Fix image number to clean 1 for STuRot, 2 for SecMng, 3 for STiRot, 0 image clear only')
@click.argument('outfile')
@click.argument('infile')
@click.option('-f', '--file', metavar='filename',default=None,
              help='code in clear to replace')
@click.command(help='''clean an ST file''')
def clean(file, infile, outfile, image_num ):
    binary=b''
    
    try:
        with open(file, 'rb') as f:
            binary=f.read()
        outputdata = image.Image.clean(infile, binary,image_num)
        if outputdata is not None:
            with open(outfile, 'wb') as f:
               f.write(outputdata)
    except Exception as e:
        print(str(e)+", Error")



@click.command(help='Print imgtool version information')
def version():
    print(imgtool_version)

@click.argument('outfile')
@click.argument('infile')
@click.option('-k', '--key', metavar='filename', required=True)
@click.option('--vector-to-sign', type=click.Choice(['payload', 'digest']), required=True,
              help='send to OUTFILE the payload or payload''s digest instead '
              'of complied image')
@click.command(help='Signed a given payload return signature')
def signature(key, vector_to_sign, infile, outfile):
    key = load_key(key)
    with open(infile, "rb") as f:
        payload = f.read()
    if isinstance(key,ECDSA256P1) or isinstance(key,ECDSA384P1) :
        key.pad_sig = True
    if vector_to_sign == 'payload':
        signature = key.sign(bytes(payload))
    elif vector_to_sign == 'digest':
        signature = key.sign_digest(bytes(payload))
    save_signature(outfile, signature)
 

@click.command(cls=AliasesGroup,
               context_settings=dict(help_option_names=['-h', '--help']))
def imgtool():
    pass


imgtool.add_command(keygen)
imgtool.add_command(getpub)
imgtool.add_command(getpubhash)
imgtool.add_command(getpriv)
imgtool.add_command(getprivbin)
imgtool.add_command(getpubbin)
imgtool.add_command(verify)
imgtool.add_command(sign)
imgtool.add_command(resign)
imgtool.add_command(version)
imgtool.add_command(dumpinfo)
imgtool.add_command(ass)
imgtool.add_command(clean)
imgtool.add_command(signature)


if __name__ == '__main__':
    imgtool()

