# Copyright 2018 Nordic Semiconductor ASA
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

"""
Image signing and management.
"""

from . import version as versmod
from imgtool.version import decode_version 
import click
import copy
from enum import Enum
import array
from intelhex import IntelHex
import hashlib
import array
import os.path
import struct
import cbor2
from enum import Enum

import click
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from intelhex import IntelHex

from . import version as versmod, keys
from .boot_record import create_sw_component_data,SwComponent
from .keys import rsa, ecdsa, x25519

from collections import namedtuple
import ctypes
c_uint8 = ctypes.c_uint8
c_uint32 = ctypes.c_uint32
class Flags_bits(ctypes.LittleEndianStructure):
    _fields_ = [
            ("pic", c_uint32, 1),
            ("primary_only", c_uint32, 1),
            ("encrypted_128", c_uint32, 1),
            ("otfdec", c_uint32, 1),
            ("non_bootable", c_uint32, 1),
            ("ram_load", c_uint32, 1),
            ("unused_1", c_uint32, 2),
            ("rom_fixed", c_uint32, 1),
            ("unused_2", c_uint32, 7+13),
            ("encrypted_256", c_uint32, 1),
            ("chip_specific", c_uint32, 1),
            ("licence_file", c_uint32, 1)
        ]

class Flags(ctypes.Union):
    _fields_ = [("b", Flags_bits),
                ("asbyte", c_uint32)]
    def __repr__(self):
        return f"Flags: pic={self.b.pic}, primary_only={self.b.primary_only}, encrypted_128={self.b.encrypted_128},encrypted_256={self.b.encrypted_256} , non_bootable={self.b.non_bootable}, ram_load={self.b.ram_load}, unused_1={self.b.unused_1}, rom_fixed={self.b.rom_fixed},otfdec={self.b.otfdec}, unused_2={self.b.unused_2}, chip_specific={self.b.chip_specific}, licence_file={self.b.licence_file}"
    def set_bit(self, field_name, value):
        if hasattr(self.b, field_name):
            setattr(self.b, field_name, 1 if value else 0)
        else:
            raise ValueError(f"Field {field_name} does not exist in Flags_bits")






IMAGE_HEADER_SIZE = 32
BIN_EXT = "bin"
INTEL_HEX_EXT = "hex"
DEFAULT_MAX_SECTORS = 128
DEFAULT_MAX_ALIGN = 8
DEP_IMAGES_KEY = "images"
DEP_VERSIONS_KEY = "versions"
MAX_SW_TYPE_LENGTH = 12  # Bytes

STiROT=[0x73ab1024]
STiROT_Image_Data=[0x55f7394e]
All_MAGIC=[0x73ab1024,0x96f3b83d,0x55f7394e]
# Image header flags.
IMAGE_F = {
        'PIC':                   0x00000001,
        'PRIMARY_ONLY':          0x00000002,
        'ENCRYPTED_AES128':      0x00000004,
        'OTFDEC':                0x00000008,
        'NON_BOOTABLE':          0x00000010,
        'RAM_LOAD':              0x00000020,
        'ROM_FIXED':             0x00000100,
        'COMPRESSED_LZMA1':      0x00000200,
        'COMPRESSED_LZMA2':      0x00000400,
        'COMPRESSED_ARM_THUMB':  0x00000800,
        'ENCRYPTED_AES256':      0x20000000,
        'CHIP_SPECIFIC':         0x40000000,
        'LICENSE_FILE':          0x80000000,
}

TLV_VALUES = {
        'KEYHASH': 0x01,
        'PUBKEY': 0x02,
        'SHA256': 0x10,
        'SHA384': 0x11,
        'SHA512': 0x12,
        'RSA2048': 0x20,
        'ECDSASIG': 0x22,
        'RSA3072': 0x23,
        'ED25519': 0x24,
        'SIG_PURE': 0x25,
        'ENCRSA2048': 0x30,
        'ENCKW': 0x31,
        'ENCEC256': 0x32,
        'ENCX25519': 0x33,
        'DEPENDENCY': 0x40,
        'SEC_CNT': 0x50,
        'BOOT_RECORD': 0x60,
        'DECOMP_SIZE': 0x70,
        'DECOMP_SHA': 0x71,
        'DECOMP_SIGNATURE': 0x72,
        'AUTH_TAG': 0x03A0,
}

TLV_SIZE = 4
TLV_INFO_SIZE = 4
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908

OverWrite = {"SHORT_OVERWRITE":1, "LONG_OVERWRITE" : 2, "NO_OVERWRITE":3}

TLV_VENDOR_RES_MIN = 0x00a0
TLV_VENDOR_RES_MAX = 0xfffe

STRUCT_ENDIAN_DICT = {
        'little': '<',
        'big':    '>'
}

VerifyResult = Enum('VerifyResult',
                    ['OK', 'INVALID_MAGIC', 'INVALID_TLV_INFO_MAGIC', 'INVALID_HASH', 'INVALID_SIGNATURE',
                     'KEY_MISMATCH'])


def align_up(num, align):
    assert (align & (align - 1) == 0) and align != 0
    return (num + (align - 1)) & ~(align - 1)


class TLV():
    def __init__(self, endian, magic=TLV_INFO_MAGIC,magic_val=None):
        self.magic = magic
        self.magic_val = magic_val
        self.buf = bytearray()
        self.endian = endian
        self.key_licence=False

    def clear(self):
        self.buf = bytearray()

    def __len__(self):
        return TLV_INFO_SIZE + len(self.buf)

    def add(self, kind, payload):
        """
        Add a TLV record.  Kind should be a string found in TLV_VALUES above.
        """
        tlv_value=None
        if isinstance(kind, int):
            tlv_value=kind
        elif kind in TLV_VALUES:
            tlv_value=TLV_VALUES[kind]
        if tlv_value is not None:
            e = STRUCT_ENDIAN_DICT[self.endian]
            buf = struct.pack(e + 'HH', tlv_value, len(payload))
            self.buf += buf
            self.buf += payload
        else:
            raise click.UsageError(f"add TLV {kind} error")

    def get(self):
        if len(self.buf) == 0:
            return bytes()
        e = STRUCT_ENDIAN_DICT[self.endian]
        header = struct.pack(e + 'HH', self.magic, len(self))
        return header + bytes(self.buf)

    def sign(self, enckey, public_key_format, payload,hash_algorithm,hash_tlv,fixed_sig):
        # Note that ecdsa wants to do the hashing itself, which means
        # we get to hash it twice.
        sha = hash_algorithm()
        sha.update(payload)
        self.digest = sha.digest()
        self.add(hash_tlv, self.digest)
        self.image_hash = self.digest
        if hasattr(self,'key') and self.key is not None:
            pubkey=self.get_public_key()
            if enckey is not None and enckey.sig_type()=="AESGCM_SHA256":
                # The key identifies the third party authority
                # public key is set in AUTH_TAG
                # A signature is also put in AUTH TAG
                if hasattr(enckey, 'sign'):
                    sig = enckey.sign(bytes(payload))
                else:
                    sig = enckey.sign_digest(self.digest)
                
                if not self.is_key_public():
                    if hasattr(self.key, 'sign'):
                        sig_auth = self.key.sign(bytes(payload))
                    else:
                        sig_auth = self.key.sign_digest(self.digest)
                    self.add(enckey.sig_tlv(), sig+pubkey+sig_auth)
                else:
                    #add sig author and pubbbytes
                    self.add(enckey.sig_tlv(), sig+pubkey)
            else:
                if public_key_format == 'hash':
                    self.add('KEYHASH', self.get_hashed_public_key_bytes(hash_algorithm))
                else:
                    self.add('PUBKEY', pubkey) 
                # `sign` expects the full image payload (sha256 done internally),
                # while `sign_digest` expects only the digest of the payload

                if hasattr(self.key, 'sign'):
                    sig = self.key.sign(bytes(payload))
                else:
                    sig = self.key.sign_digest(self.digest)
                self.add(self.key.sig_tlv(), sig)
        elif fixed_sig is not None:
            if public_key_format == 'hash':
                self.add('KEYHASH', self.get_hashed_public_key_bytes(hash_algorithm))
            else:
                self.add('PUBKEY', pubkey) 
            # `sign` expects the full image payload (sha256 done internally),
            # while `sign_digest` expects only the digest of the payload
            # force ECDSA key to max size.
            if isinstance(self.pub_key, ecdsa.ECDSA256P1Public):
                fixed_sig['value'] = ecdsa.ECDSA256P1.build_uncompress_signature(self,fixed_sig['value'])
            if isinstance(self.pub_key, ecdsa.ECDSA384P1Public):
                fixed_sig['value'] = ecdsa.ECDSA384P1.build_uncompress_signature(self,fixed_sig['value'])
            self.add(self.pub_key.sig_tlv(), fixed_sig['value'])
            self.signature = fixed_sig['value']
      
    def add_fake_tlv(self,length):
            if length:
                e = STRUCT_ENDIAN_DICT[self.endian]
                if length>=TLV_SIZE:
                    padding=length -TLV_SIZE
                else:
                    padding=length + 16
                buf = struct.pack(e + 'HH', TLV_VALUES['BOOT_RECORD'], padding)
                self.buf += buf+bytearray([0]*padding)
    
    def set_key(self, key):
            self.key=key
    
    def unset_key(self):
            self.key=None

    def set_pub_key(self, pub_key):
            self.pub_key=pub_key
        
    def is_key_public(self):
        if "Public" in self.key.__class__.__name__:
            return True
        else:
                return False

    def get_public_key(self):
        if hasattr(self,'key')  and self.key is not None:
            return self.key.get_public_bytes()
        else:
            return None
        
    def get_hashed_public_key_bytes(self,hash_algorithm):
        if hasattr(self,'key') and self.key is not None:
            publicKey = self.key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(publicKey)
            return sha.digest()
        elif self.pub_key is not None:
            publicKey = self.pub_key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(publicKey)
            return sha.digest()
        else:
            return bytes(hashlib.sha256().digest_size)

    def clear(self):
        self.buf = bytearray()

    def add_key(self,enckey, plainkey):
        if isinstance(enckey, rsa.RSAPublic):
            cipherkey = enckey._get_public().encrypt(
                plainkey, padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None))
            
            enctlv_len = len(cipherkey)
            self.add('ENCRSA2048', cipherkey)
        elif isinstance(enckey, (ecdsa.ECDSA256P1Public,
                                 x25519.X25519Public)):
            cipherkey, mac, pubk = TLV._ecies_hkdf(enckey, plainkey)
            enctlv = pubk + mac + cipherkey
            enctlv_len = len(enctlv)
            if isinstance(enckey, ecdsa.ECDSA256P1Public):
                self.add('ENCEC256', enctlv)
            else:
                self.add('ENCX25519', enctlv)
        elif self.key_licence:
            enctlv_len=0
        else:
            raise click.UsageError("unknown key")
        return enctlv_len

       
    def _ecies_hkdf(enckey, plainkey):
        if isinstance(enckey, ecdsa.ECDSA256P1Public):
            newpk = ec.generate_private_key(ec.SECP256R1(), default_backend())
            shared = newpk.exchange(ec.ECDH(), enckey._get_public())
        else:
            newpk = X25519PrivateKey.generate()
            shared = newpk.exchange(enckey._get_public())
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32+len(plainkey), salt=None,
            info=b'MCUBoot_ECIES_v1', backend=default_backend()).derive(shared)
        encryptor = Cipher(algorithms.AES(derived_key[:len(plainkey)]),
                           modes.CTR(bytes([0] * 16)),
                           backend=default_backend()).encryptor()
        cipherkey = encryptor.update(plainkey) + encryptor.finalize()
        mac = hmac.HMAC(derived_key[len(plainkey):], hashes.SHA256(),
                        backend=default_backend())
        mac.update(cipherkey)
        ciphermac = mac.finalize()
        if isinstance(enckey, ecdsa.ECDSA256P1Public):
            pubk = newpk.public_key().public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.UncompressedPoint)
        else:
            pubk = newpk.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw)
        return cipherkey, ciphermac, pubk


SHAAndAlgT = namedtuple('SHAAndAlgT', ['sha', 'alg'])

TLV_SHA_TO_SHA_AND_ALG = {
    TLV_VALUES['SHA256'] : SHAAndAlgT('256', hashlib.sha256),
    TLV_VALUES['SHA384'] : SHAAndAlgT('384', hashlib.sha384),
    TLV_VALUES['SHA512'] : SHAAndAlgT('512', hashlib.sha512),
}


USER_SHA_TO_ALG_AND_TLV = {
    'auto'   : (hashlib.sha256, 'SHA256'),
    '256'    : (hashlib.sha256, 'SHA256'),
    '384'    : (hashlib.sha384, 'SHA384'),
    '512'    : (hashlib.sha512, 'SHA512')
}


def is_sha_tlv(tlv):
    return tlv in TLV_SHA_TO_SHA_AND_ALG.keys()


def tlv_sha_to_sha(tlv):
    return TLV_SHA_TO_SHA_AND_ALG[tlv].sha


# Auto selecting hash algorithm for type(key)
ALLOWED_KEY_SHA = {
    keys.ECDSA384P1         : ['384'],
    keys.ECDSA384P1Public   : ['384'],
    keys.ECDSA256P1         : ['256'],
    keys.ECDSA256P1Public   : ['256'],
    keys.RSA                : ['256'],
    keys.RSAPublic          : ['256'],
    # This two are set to 256 for compatibility, the right would be 512
    keys.Ed25519            : ['256', '512'],
    keys.X25519             : ['256', '512']
}

def key_and_user_sha_to_alg_and_tlv(key, user_sha):
    """Matches key and user requested sha to sha alogrithm and TLV name.

       The returned tuple will contain hash functions and TVL name.
       The function is designed to succeed or completely fail execution,
       as providing incorrect pair here basically prevents doing
       any more work.
    """
    if key is None:
        # If key is none, we allow whatever user has selected for sha
        return USER_SHA_TO_ALG_AND_TLV[user_sha]

    # If key is not None, then we have to filter hash to only allowed
    allowed = None
    try:
        allowed = ALLOWED_KEY_SHA[type(key)]
    except KeyError:
        raise click.UsageError("Could not find allowed hash algorithms for {}"
                               .format(type(key)))
    if user_sha == 'auto':
        return USER_SHA_TO_ALG_AND_TLV[allowed[0]]

    if user_sha in allowed:
        return USER_SHA_TO_ALG_AND_TLV[user_sha]

    raise click.UsageError("Key {} can not be used with --sha {}; allowed sha are one of {}"
                           .format(key.sig_type(), user_sha, allowed))


def get_digest(tlv_type, hash_region):
    sha = TLV_SHA_TO_SHA_AND_ALG[tlv_type].alg()

    sha.update(hash_region)
    return sha.digest()


def tlv_matches_key_type(tlv_type, key):
    """Check if provided key matches to TLV record in the image"""
    try:
        # We do not need the result here, and the key_and_user_sha_to_alg_and_tlv
        # will either succeed finding match or rise exception, so on success we
        # return True, on exception we return False.
        _, _ = key_and_user_sha_to_alg_and_tlv(key, tlv_sha_to_sha(tlv_type))
        return True
    except:
        pass

    return False



class Image:
    def STiROTlist():
        return " ".join(hex(x) for x in STiROT)
    def __init__(self, version=None, header_size=IMAGE_HEADER_SIZE,
                 pad_header=False, pad=False, confirm=False, align=1,
                 slot_size=0, max_sectors=DEFAULT_MAX_SECTORS,
                 overwrite_only=False, endian="little", load_addr=0,
                 rom_fixed=None, erased_val=None, save_enctlv=False,
                 security_counter=None, max_align=None, magic_val=0x96f3b83d,
                 non_bootable=False, no_pad_tlv=True):

        if load_addr and rom_fixed:
            raise click.UsageError("Can not set rom_fixed and load_addr at the same time")

        self.image_hash = None
        self.image_size = None
        self.signature = None
        self.version = version or versmod.decode_version("0")
        self.header_size = header_size
        self.pad_header = pad_header
        self.pad = pad
        self.confirm = confirm
        self.align = align
        self.slot_size = slot_size
        self.max_sectors = max_sectors
        if magic_val in STiROT:
            self.overwrite_only=OverWrite["SHORT_OVERWRITE"]
        elif overwrite_only:
            self.overwrite_only=OverWrite["LONG_OVERWRITE"]
        else:
            self.overwrite_only=OverWrite["NO_OVERWRITE"]
        self.endian = endian
        self.base_addr = None
        self.load_addr = 0 if load_addr is None else load_addr
        self.rom_fixed = rom_fixed
        self.erased_val = 0xff if erased_val is None else int(erased_val, 0)
        self.payload = []
        self.infile_data = []
        self.enckey = None
        self.save_enctlv = save_enctlv
        self.enctlv_len = 0
        self.max_align = max(DEFAULT_MAX_ALIGN, align) if max_align is None else int(max_align)
        self.magic_val= magic_val
        self.non_bootable = non_bootable
        self.no_pad_tlv=no_pad_tlv
        self.boot_magic = bytes([
                0x77, 0xc2, 0x95, 0xf3,
                0x60, 0xd2, 0xef, 0x7f,
                0x35, 0x52, 0x50, 0x0f,
                0x2c, 0xb6, 0x79, 0x80, ])
        self.primary_only = False
        
        if security_counter == 'auto':
            # Security counter has not been explicitly provided,
            # generate it from the version number
            self.security_counter = ((self.version.major << 24)
                                     + (self.version.minor << 16)
                                     + self.version.revision)
        else:
            self.security_counter = security_counter
        self.vector_to_sign = None
        self.otfdec = False
    def __repr__(self):
        ow=list(OverWrite.keys())[list(OverWrite.values()).index(self.overwrite_only)]
        return "<Image version={}, header_size={}, security_counter={}, \
                base_addr={}, load_addr={}, align={}, slot_size={}, \
                max_sectors={}, overwrite_only={}, endian={} format={}, \
                payloadlen=0x{:x}>".format(
                    self.version,
                    self.header_size,
                    hex(self.security_counter),
                    hex(self.base_addr) if self.base_addr is not None else "N/A",
                    hex(self.load_addr),
                    self.align,
                    hex(self.slot_size),
                    self.max_sectors,
                    ow,
                    self.endian,
                    self.__class__.__name__,
                    len(self.payload))

    def load(self, path):
        """Load an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()
        try:
            if ext == INTEL_HEX_EXT:
                ih = IntelHex(path)
                self.infile_data = ih.tobinarray()
                self.payload = copy.copy(self.infile_data)
                self.base_addr = ih.minaddr()
            else:
                with open(path, 'rb') as f:
                    self.infile_data = f.read()
                    self.payload = copy.copy(self.infile_data)
        except FileNotFoundError:
            raise click.UsageError("Input file not found")
        self.image_size = len(self.payload)

        # Add the image header if needed.
        if self.pad_header and self.header_size > 0:
            if self.base_addr:
                # Adjust base_addr for new header
                self.base_addr -= self.header_size
            self.payload = bytes([self.erased_val] * self.header_size) + \
                self.payload

        self.check_header()

    def load_compressed(self, data, compression_header):
        """Load an image from buffer"""
        self.payload = compression_header + data
        self.image_size = len(self.payload)

        # Add the image header if needed.
        if self.pad_header and self.header_size > 0:
            if self.base_addr:
                # Adjust base_addr for new header
                self.base_addr -= self.header_size
            self.payload = bytes([self.erased_val] * self.header_size) + \
                self.payload

        self.check_header()

    def save(self, path, hex_addr=None):
        """Save an image from a given file"""
        ext = os.path.splitext(path)[1][1:].lower()
        if ext == INTEL_HEX_EXT:
            # input was in binary format, but HEX needs to know the base addr
            if self.base_addr is None and hex_addr is None:
                raise click.UsageError("No address exists in input file "
                                       "neither was it provided by user")
            h = IntelHex()
            if hex_addr is not None:
                self.base_addr = hex_addr
            h.frombytes(bytes=self.payload, offset=self.base_addr)
            if self.pad and self.vector_to_sign is None:
                trailer_size = self._trailer_size(self.align, self.max_sectors,
                                                  self.overwrite_only,
                                                  self.enckey,
                                                  self.save_enctlv,
                                                  self.enctlv_len)
                trailer_addr = (self.base_addr + self.slot_size) - trailer_size
                if self.confirm and OverWrite["NO_OVERWRITE"]==self.overwrite_only:
                    magic_align_size = align_up(len(self.boot_magic),
                                                self.max_align)
                    image_ok_idx = -(magic_align_size + self.max_align)
                    flag = bytearray([self.erased_val] * self.max_align)
                    flag[0] = 0x01  # image_ok = 0x01
                    h.puts(trailer_addr + trailer_size + image_ok_idx,
                           bytes(flag))
                h.puts(trailer_addr + (trailer_size - len(self.boot_magic)),
                       bytes(self.boot_magic))
            h.tofile(path, 'hex')
            
        else:
            if self.pad and self.vector_to_sign is None:
                self.pad_to(self.slot_size)
            with open(path, 'wb') as f:
                f.write(self.payload)
           
    def check_header(self):
        if self.header_size > 0 and not self.pad_header:
            if any(v != 0 for v in self.payload[0:self.header_size]):
                raise click.UsageError("Header padding was not requested and "
                                       "image does not start with zeros")

    def check_trailer(self):
        if self.slot_size > 0:
            tsize = self._trailer_size(self.align, self.max_sectors,
                                       self.overwrite_only, self.enckey,
                                       self.save_enctlv, self.enctlv_len)
            padding = self.slot_size - (len(self.payload) + tsize)
            if padding < 0:
                msg = "Image size (0x{:x}) + trailer (0x{:x}) exceeds " \
                      "requested size 0x{:x}".format(
                          len(self.payload), tsize, self.slot_size)
                raise click.UsageError(msg)

    def create(self, key, public_key_format, enckey, dependencies=None,
               sw_type=None, custom_tlvs=None, compression_tlvs=None,
               compression_type=None, encrypt_keylen=128, clear=False,
               fixed_sig=None, pub_key=None, vector_to_sign=None, user_sha='auto',
                 temporary_key=None,licence=None,primary_only=False,otfdec=None):
        self.enckey = enckey
        self.vector_to_sign = vector_to_sign
        self.primary_only = primary_only
        if self.primary_only:
            image_flag = 'PRIMARY_ONLY'
        elif otfdec is not None:
            image_flag = 'OTFDEC'
            self.otfdec = True
        else:
            image_flag = False
        # key decides on sha, then pub_key; of both are none default is used
        check_key = key if key is not None else pub_key
        hash_algorithm, hash_tlv = key_and_user_sha_to_alg_and_tlv(check_key, user_sha)

        # Calculate the hash of the public key
        if key is not None:
            pub = key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(pub)
            pubbytes = sha.digest()
        elif pub_key is not None:
            pub = pub_key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(pub)
            pubbytes = sha.digest()
        else:
            pubbytes = bytes(hashlib.sha256().digest_size)

        tlv = TLV(self.endian,magic_val=self.magic_val)
        tlv.set_key(key)
        tlv.set_pub_key(pub_key)
        
        if sw_type is not None:
            if len(sw_type) > MAX_SW_TYPE_LENGTH:
                msg = "'{}' is too long ({} characters) for sw_type. Its " \
                      "maximum allowed length is 12 characters.".format(
                       sw_type, len(sw_type))
                raise click.UsageError(msg)

            image_version = (str(self.version.major) + '.'
                             + str(self.version.minor) + '.'
                             + str(self.version.revision))

            # The image hash is computed over the image header, the image
            # itself and the protected TLV area. However, the boot record TLV
            # (which is part of the protected area) should contain this hash
            # before it is even calculated. For this reason the script fills
            # this field with zeros and the bootloader will insert the right
            # value later.
            digest = bytes(hash_algorithm().digest_size)

            # Create CBOR encoded boot record
            boot_record = create_sw_component_data(sw_type, image_version,
                                                   hash_tlv, digest,
                                                   pubbytes)
        else:
            boot_record=None
        
        # At this point the image is already on the payload
        #
        # This adds the padding if image is not aligned to the 16 Bytes
        # in encrypted mode
        if self.enckey is not None:
            if self.enckey.sig_type()=="AESGCM_SHA256":
                # in this mode binary is always encrypted
                # force enkey to symetric key
                # plain_key is the AES-GCM key
                if not licence:
                    raise click.UsageError("inappropriate key")
                plainkey = self.enckey.get_private_bytes(format=None)
                tlv.key_licence = True
            else:
                # plain key is i not a licence file, then random
                if encrypt_keylen == 256:
                    plainkey = os.urandom(32)
                else:
                    plainkey = os.urandom(16)

            # This adds the padding if image is not aligned to the 16 Bytes
            # in encrypted mode
            pad_len = len(self.payload) % 16
            if pad_len > 0:
                pad = bytes(16 - pad_len)
                if isinstance(self.payload, bytes):
                    self.payload += pad
                else:
                    self.payload.extend(pad)
        else:
            plainkey=None


        compression_flags = 0x0
        if compression_tlvs is not None:
            if compression_type in ["lzma2", "lzma2armthumb"]:
                compression_flags = IMAGE_F['COMPRESSED_LZMA2']
                if compression_type == "lzma2armthumb":
                    compression_flags |= IMAGE_F['COMPRESSED_ARM_THUMB']
              

        # This adds the header to the payload as well
        endof_payload_section=len(self.payload)
         # Protected TLVs must be added first, because they are also included
        # in the hash calculation
        if not self.otfdec:
            if boot_record or dependencies or len(custom_tlvs) > 0 or self.security_counter is not None:
                prot_tlv=self._build_prot_tlv(boot_record, dependencies, compression_tlvs, custom_tlvs, None)
                # header have to be set before sign
                self.add_header(enckey, len(prot_tlv),compression_flags,endof_payload_section,
                                encrypt_keylen,chip_licence = licence,image_flag=image_flag)
                
                if self.magic_val in STiROT and not tlv.key_licence:
                    # Use temporary key to be able to calculate padding
                    if key is None:
                       tlv.set_key(temporary_key)
                    tlv.sign(enckey, public_key_format, self.payload+prot_tlv.get(),hash_algorithm,hash_tlv,None)
                    # remove temporary key
                    if key is None:
                        tlv.unset_key()
                        
                else:  
                    if vector_to_sign is not None:
                        self.payload += prot_tlv.get()
                        if vector_to_sign == 'digest':
                            sha = hash_algorithm()
                            sha.update(self.payload)
                            self.digest = sha.digest()
                            self.payload = self.digest
                        return 
                    tlv.sign(enckey, public_key_format, self.payload+prot_tlv.get(),hash_algorithm,hash_tlv,fixed_sig)
                
            else:
                prot_tlv = None 
                prot_tlv_size = 0 
                # header have to be set before sign
                self.add_header(enckey, prot_tlv_size,compression_flags,endof_payload_section,
                                encrypt_keylen,chip_licence = licence,image_flag=image_flag)
                tlv.sign(enckey, public_key_format, self.payload,hash_algorithm,hash_tlv,fixed_sig)
            if enckey is not None:
                self.enctlv_len=tlv.add_key(enckey, plainkey)
                if self.magic_val in STiROT and not tlv.key_licence: # no_pad_tlv
                    if not boot_record and not dependencies and not custom_tlvs and not self.security_counter:
                        raise click.UsageError('Need protected TLV for this magic, error')
                    traileur_size=self._trailer_size(self.align, self.max_sectors,
                                        self.overwrite_only, self.enckey,
                                        self.save_enctlv, self.enctlv_len)
                    free=self.slot_size-endof_payload_section-len(tlv)-len(prot_tlv)-traileur_size
                    
                    if self.no_pad_tlv:
                        empty_zone=free % 16
                        self.payload +=bytearray([0] * (free-empty_zone))
                        endof_payload_section+=free-empty_zone
                        prot_tlv=self._build_prot_tlv(boot_record, dependencies, compression_tlvs, custom_tlvs, None)
                    else:
                        len_fake_tlv=free % 16
                        if len_fake_tlv<5:
                            len_fake_tlv=16+len_fake_tlv
                        self.payload +=bytearray([0] * (free-len_fake_tlv))
                        endof_payload_section+=free-len_fake_tlv
                        prot_tlv=self._build_prot_tlv(boot_record, dependencies, compression_tlvs, custom_tlvs, len_fake_tlv)
                        
                    # then rebuild tlv with the new signature
                    tlv.clear()
                    self.add_header(enckey, len(prot_tlv),compression_flags, endof_payload_section,
                                    encrypt_keylen,chip_licence = licence,image_flag=image_flag)
                    if vector_to_sign is not None:
                        self.payload += prot_tlv.get()
                        if vector_to_sign == 'digest':
                            sha = hash_algorithm()
                            sha.update(self.payload)
                            self.digest = sha.digest()
                            self.payload = self.digest
                        return
                    tlv.sign(enckey,public_key_format, self.payload+prot_tlv.get(),hash_algorithm,hash_tlv,fixed_sig)
                    
                    self.enctlv_len=tlv.add_key(enckey, plainkey)
                if tlv.key_licence:
                   nonce=tlv.digest[16:]
                else:
                   nonce = bytes([0] * 16)
                # Encrypt 
                if type(self.payload)!=bytearray:
                        self.payload=bytearray(self.payload)
                img=self._crypt(plainkey, nonce)
                if clear == False:
                    self.payload[self.header_size:] = img
            else:
                self.add_header(enckey, len(prot_tlv),compression_flags,endof_payload_section,
                                chip_licence = licence,image_flag=image_flag)
            if self.primary_only:
                self.add_header(enckey, len(prot_tlv),compression_flags,endof_payload_section,
                                force_encrypted=True,chip_licence = licence,image_flag=image_flag)
            if prot_tlv:
                self.payload += prot_tlv.get()
            self.payload += tlv.get()
            self.check_trailer()
        else:
            if boot_record or dependencies or custom_tlvs or self.security_counter:
                prot_tlv=self._build_prot_tlv(boot_record, dependencies,compression_tlvs, custom_tlvs, None)
            else:
                prot_tlv = TLV(self.endian, TLV_PROT_INFO_MAGIC)
            if enckey is not None:
                self.enctlv_len=tlv.add_key(enckey, plainkey)
                nonce=bytes([0] * 16)
                img=self._crypt(plainkey, nonce)
                if clear==False:
                    if type(self.payload)!=bytearray:
                        self.payload=bytearray(self.payload) 
                    self.payload[self.header_size:] = img
            self.add_header(enckey, len(prot_tlv),compression_flags,endof_payload_section, chip_licence = licence, image_flag=image_flag)
            # add the protected TLV 
            self.payload += prot_tlv.get()
            tlv.sign(enckey, public_key_format, self.payload,hash_algorithm,hash_tlv,fixed_sig)
            self.payload += tlv.get()
            self.check_trailer()
        
    def get_struct_endian(self):
        return STRUCT_ENDIAN_DICT[self.endian]

    def get_signature(self):
        return self.signature

    def get_infile_data(self):
        return self.infile_data

    def add_header(self, enckey, protected_tlv_size, compression_flags, endof_payload_section, aes_length=128, force_encrypted=False, chip_licence=None, image_flag=False):
        """Install the image header."""
        flags = 0
        if enckey is not None:

          # encrypted primary image only has hash computed on a header without flag encrypted. 
            if not image_flag:
                if enckey.sig_type()!="AESGCM_SHA256":
                    if aes_length == 128:
                        flags |= IMAGE_F['ENCRYPTED_AES128']
                    else:
                        flags |= IMAGE_F['ENCRYPTED_AES256']
                else:
                    flags |= IMAGE_F['LICENSE_FILE']
                    if chip_licence == '1':
                        flags |= IMAGE_F['CHIP_SPECIFIC']
            if force_encrypted:
                if aes_length == 128:
                    flags |= IMAGE_F['ENCRYPTED_AES128']
                else:
                    flags |= IMAGE_F['ENCRYPTED_AES256']
            
        if self.load_addr != 0:
            # Indicates that this image should be loaded into RAM
            # instead of run directly from flash.
            flags |= IMAGE_F['RAM_LOAD']
        # As we use slot index value between 0 to 3 we need to test if value is not None instead of value itself (0 is false).
        if self.rom_fixed is not None:
            flags |= IMAGE_F['ROM_FIXED']
        if self.non_bootable:
            flags |= IMAGE_F['NON_BOOTABLE']
        if image_flag:
            flags |= IMAGE_F[image_flag]

        e = STRUCT_ENDIAN_DICT[self.endian]
        fmt = (e +
               # type ImageHdr struct {
               'I' +     # Magic    uint32
               'I' +     # LoadAddr uint32
               'H' +     # HdrSz    uint16
               'H' +     # PTLVSz   uint16
               'I' +     # ImgSz    uint32
               'I' +     # Flags    uint32
               'BBHI' +  # Vers     ImageVersion
               'I'       # Pad1     uint32
               )  # }
        assert struct.calcsize(fmt) == IMAGE_HEADER_SIZE
        header = struct.pack(fmt,
                             self.magic_val,
                             self.rom_fixed or self.load_addr,
                             self.header_size,
                             protected_tlv_size,  # TLV Info header + Protected TLVs
                             endof_payload_section - self.header_size,  # ImageSz
                             flags | compression_flags,
                             self.version.major,
                             self.version.minor or 0,
                             self.version.revision or 0,
                             self.version.build or 0,
                             0)  # Pad1
        self.payload = bytearray(self.payload)
        self.payload[:len(header)] = header

    def _trailer_size(self, write_size, max_sectors, mode, enckey,
                      save_enctlv, enctlv_len):
        # NOTE: should already be checked by the argument parser
        magic_size = 16
        if self.primary_only:
            return magic_size
        magic_align_size = align_up(magic_size, self.max_align)
        if mode==OverWrite["SHORT_OVERWRITE"]:
            return self.max_align  + magic_size
        if mode==OverWrite["LONG_OVERWRITE"]:
            return self.max_align * 2 + magic_size
        else:
            if write_size not in set([1, 2, 4, 8, 16, 32]):
                raise click.BadParameter("Invalid alignment: {}".format(
                    write_size))
            m = DEFAULT_MAX_SECTORS if max_sectors is None else max_sectors
            trailer = m * 3 * write_size  # status area
            if enckey is not None:
                if save_enctlv:
                    # TLV saved by the bootloader is aligned
                    keylen = align_up(enctlv_len, self.max_align)
                else:
                    keylen = align_up(16, self.max_align)
                trailer += keylen * 2  # encryption keys
            trailer += self.max_align * 4  # image_ok/copy_done/swap_info/swap_size
            trailer += magic_align_size
            return trailer

    def pad_to(self, size):
        """Pad the image to the given size, with the given flash alignment."""
        tsize = self._trailer_size(self.align, self.max_sectors,
                                   self.overwrite_only, self.enckey,
                                   self.save_enctlv, self.enctlv_len)
        padding = size - (len(self.payload) + tsize)
        pbytes = bytearray([self.erased_val] * padding)
        pbytes += bytearray([self.erased_val] * (tsize - len(self.boot_magic)))
        pbytes += self.boot_magic
        if self.confirm and OverWrite["NO_OVERWRITE"]==self.overwrite_only:
            magic_size = 16
            magic_align_size = align_up(magic_size, self.max_align)
            image_ok_idx = -(magic_align_size + self.max_align)
            pbytes[image_ok_idx] = 0x01  # image_ok = 0x01
        self.payload += pbytes

    @staticmethod
    def verify(imgfile, key):
        ext = os.path.splitext(imgfile)[1][1:].lower()
        try:
            if ext == INTEL_HEX_EXT:
                b = IntelHex(imgfile).tobinstr()
            else:
                with open(imgfile, 'rb') as f:
                    b = f.read()
        except FileNotFoundError:
            raise click.UsageError(f"Image file {imgfile} not found")
        magic, _, header_size, _, img_size = struct.unpack('IIHHI', b[:16])
        version = struct.unpack('BBHI', b[20:28])
        if magic not in All_MAGIC:
            return VerifyResult.INVALID_MAGIC, None, None
        tlv_off = header_size + img_size
        tlv_info = b[tlv_off:tlv_off + TLV_INFO_SIZE]
        magic, tlv_tot = struct.unpack('HH', tlv_info)
        if magic == TLV_PROT_INFO_MAGIC:
            tlv_off += tlv_tot
            tlv_info = b[tlv_off:tlv_off + TLV_INFO_SIZE]
            magic, tlv_tot = struct.unpack('HH', tlv_info)

        if magic != TLV_INFO_MAGIC:
            return VerifyResult.INVALID_TLV_INFO_MAGIC, None, None

        prot_tlv_size = tlv_off
        hash_region = b[:prot_tlv_size]
        digest = None
        tlv_end = tlv_off + tlv_tot
        tlv_off += TLV_INFO_SIZE  # skip tlv info
        while tlv_off < tlv_end:
            tlv = b[tlv_off:tlv_off + TLV_SIZE]
            tlv_type, _, tlv_len = struct.unpack('BBH', tlv)
            if is_sha_tlv(tlv_type):
                if not tlv_matches_key_type(tlv_type, key):
                    return VerifyResult.KEY_MISMATCH, None, None
                off = tlv_off + TLV_SIZE
                digest = get_digest(tlv_type, hash_region)
                if digest == b[off:off + tlv_len]:
                    if key is None:
                        return VerifyResult.OK, version, digest
                else:
                    return VerifyResult.INVALID_HASH, None, None
            elif key is not None and tlv_type == TLV_VALUES[key.sig_tlv()]:
                off = tlv_off + TLV_SIZE
                tlv_sig = b[off:off + tlv_len]
                payload = b[:prot_tlv_size]
                try:
                    if hasattr(key, 'verify'):
                        key.verify(tlv_sig, payload)
                    else:
                        key.verify_digest(tlv_sig, digest)
                    return VerifyResult.OK, version, digest
                except InvalidSignature:
                    # continue to next TLV
                    pass
            tlv_off += TLV_SIZE + tlv_len
        return VerifyResult.INVALID_SIGNATURE, None, None

    def _build_prot_tlv(self, boot_record, dependencies,compression_tlvs, custom_tlvs, fake_padding) :
        prot_tlv = TLV(self.endian, TLV_PROT_INFO_MAGIC)

        e = STRUCT_ENDIAN_DICT[self.endian]

        if self.security_counter is not None:
            payload = struct.pack(e + 'I', self.security_counter)
            prot_tlv.add('SEC_CNT', payload)

        if fake_padding is not None and fake_padding:
            prot_tlv.add_fake_tlv(fake_padding)
        
        if boot_record is not None:
            prot_tlv.add('BOOT_RECORD', boot_record)

        if dependencies is not None:
            for i in range(len(dependencies[DEP_IMAGES_KEY])):
                payload = struct.pack(
                                e + 'B3x'+'BBHI',
                                int(dependencies[DEP_IMAGES_KEY][i]),
                                dependencies[DEP_VERSIONS_KEY][i].major,
                                dependencies[DEP_VERSIONS_KEY][i].minor,
                                dependencies[DEP_VERSIONS_KEY][i].revision,
                                dependencies[DEP_VERSIONS_KEY][i].build
                                )
                prot_tlv.add('DEPENDENCY', payload)

        if compression_tlvs is not None:
            for tag, value in compression_tlvs.items():
                prot_tlv.add(tag, value)

        if custom_tlvs is not None:
            for tag, value in custom_tlvs.items():
                prot_tlv.add(tag, value)
        return prot_tlv      

    def _crypt(self, plainkey, nonce):
        cipher = Cipher(algorithms.AES(plainkey), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        img = bytes(self.payload[self.header_size:])
        if not self.otfdec:
            img = encryptor.update(img) + encryptor.finalize()
        else:
            toadd = (16-len(img)%16)
            img += toadd*b'0'
            img = self._swap_bytes_in_blocks(img,16)
            img = encryptor.update(img) + encryptor.finalize()
            img = self._swap_bytes_in_blocks(img,16)
            img = img[:-toadd]
        return img
    
    @staticmethod            
    def resign(imgfile, key, public_key_format, hex_addr, overwrite_only,
               endian, align, confirm, pad, save_enctlv, erased_val, slot_size, max_sectors):
        with open(imgfile, "rb") as f:
            b = f.read()
        # decode header
        magic, Load_addr, header_size, ptlvs, img_size, flags = struct.unpack('IIHHII', b[:20])
        version = struct.unpack('BBHI', b[20:28])
        decodedflags = Flags()
        decodedflags.asbyte = flags
        if not decodedflags.b.licence_file:
            raise click.UsageError("no licence flag "+ str(flags))
        # dummy parameter for image creation, image is created to use img save method
        img = Image(version=decode_version("0.0.0"), header_size=header_size,
                      pad_header=0, pad=pad, confirm=confirm,
                      align=int(align), slot_size=slot_size,
                      max_sectors=max_sectors, overwrite_only=overwrite_only,
                      endian=endian, load_addr=0x0, rom_fixed=False,
                      erased_val=erased_val, save_enctlv=save_enctlv,
                      security_counter='auto')
        # protected TLV header to modify is here
        tlv_nonprotected_off = header_size + img_size + ptlvs
        tlv_info=b[tlv_nonprotected_off:tlv_nonprotected_off + TLV_INFO_SIZE]
        magic, tlv_tot = struct.unpack('HH', tlv_info)
        if magic!=TLV_INFO_MAGIC:
            raise click.UsageError("magic error")
        # start of protected tlv
        tlv_off = tlv_nonprotected_off+ TLV_INFO_SIZE
        tlv_end = tlv_nonprotected_off + tlv_tot
        digest=None
        # parse all protected TLV to check 
        # sha256 is present, and no signature, no public key
        # recreate tlv unprotected with all info present
        unprot_tlv = TLV(endian, TLV_INFO_MAGIC)
        while tlv_off < tlv_end:
            tlv = b[tlv_off:tlv_off+TLV_SIZE]
            tlv_type, tlv_len = struct.unpack('HH', tlv)
            #get TLV string value
            off = tlv_off + TLV_SIZE
            if tlv_type == TLV_VALUES["SHA256"]:
                digest=b[off:off+tlv_len]
            if tlv_type == TLV_VALUES["SHA384"]:
                digest=b[off:off+tlv_len]
            if tlv_type == TLV_VALUES["KEYHASH"]:
                raise click.UsageError("Unexpected KEYHASH")
            if tlv_type == TLV_VALUES["PUBKEY"]:
                raise click.UsageError("Unexpected PUBKEY")
            if tlv_type == TLV_VALUES["RSA2048"]:
                raise click.UsageError("Unexpected RSA2048")
            if tlv_type == TLV_VALUES["ECDSASIG"]:
                raise click.UsageError("Unexpected ECDSASIG")
            if tlv_type == TLV_VALUES["RSA3072"]:
                raise click.UsageError("Unexpected RSA3072")
            if tlv_type == TLV_VALUES["ED25519"]:
                raise click.UsageError("Unexpected ED25519")
            unprot_tlv.add(tlv_type,b[off:off+tlv_len])
            tlv_off+= TLV_SIZE + tlv_len
        if digest is None:
            raise click.UsageError("No digest")
        
        # key decides on sha, then pub_key; of both are none default is used
        hash_algorithm, hash_tlv = key_and_user_sha_to_alg_and_tlv(key, 'auto')

        # compute Key value to be put in tlv
        if key is not None:
            pub = key.get_public_bytes()
            sha = hash_algorithm()
            sha.update(pub)
            pubbytes = sha.digest()
        else:
            pubbytes = bytes(hashlib.sha256().digest_size)
        # add key info to protlv
        if public_key_format == 'hash':
            unprot_tlv.add('KEYHASH', pubbytes)
        else:
            unprot_tlv.add('PUBKEY', pub)
        # compute signature from sha256 hash
        signature = key.sign_digest(digest)
        # add signature to protlv
        unprot_tlv.add(key.sig_tlv(),signature)
        # build img new payload file
        img.payload=b[:header_size + img_size + ptlvs]
        img.payload+=unprot_tlv.get()
        return img

    def clean(imgfile, binary, image_type):
        with open(imgfile, "rb") as f:
            b = f.read()
        outbinary=b''
        # Magic    uint32
        # LoadAddr uint32
        # HdrSz    uint16
        # PTLVSz   uint16
        # ImgSz    uint32
        # Flags    uint32
        # Vers :    
        # iv_major uint8;
        # iv_minor uint8;
        # iv_revision uint16;
        # iv_build_num uint32;
        magic, Load_addr, header_size, ptlvs, img_size, flags = struct.unpack('IIHHII', b[:20])
        # padd binary with 0 to align on 16 bytes
        offset_key_size = 0
        pad_len = len(binary) % 16
        if pad_len > 0:
            pad = bytes(16 - pad_len)
            binary+=pad
        if magic in STiROT and img_size>len(binary):
            pad = bytes(img_size - len(binary))
            binary+=pad
        if img_size == len(binary):
            offset = header_size+img_size
            header=b[:header_size]+binary+b[header_size+len(binary):header_size+img_size]
            val_cleaned=b'\0'*32
            pubkey_cleaned=b'\0'*91
            tlv_off=offset+TLV_INFO_SIZE
            tlv_info = b[offset:tlv_off]
            magic_tlv, tlv_len_size = struct.unpack('HH', tlv_info)      
            if image_type in [ 1, 2 ]: 
                if magic_tlv == TLV_PROT_INFO_MAGIC:
                    outbinary = tlv_info
                    end_tlv_prot=tlv_off+tlv_len_size-TLV_INFO_SIZE
                    while tlv_off < end_tlv_prot:
                        tlv_info=b[tlv_off:tlv_off+TLV_SIZE]
                        tlv_type, tlv_len = struct.unpack('HH', tlv_info) 
                        end_tlv=tlv_off+tlv_len+TLV_SIZE
                        tlv_value = b[tlv_off+TLV_SIZE:tlv_off+TLV_SIZE+tlv_len]
                        # get TLV string value
                        if tlv_type==TLV_VALUES['BOOT_RECORD']:
                            boot_record = b[tlv_off:end_tlv]
                            decoded_data = cbor2.loads(bytes(tlv_value))
                            for key, value in decoded_data.items():
                                key_bytes = cbor2.dumps(key)
                                if int.from_bytes(key_bytes, byteorder='big') == SwComponent.SIGNER_ID:
                                    pub_key_hash = value
                            if pub_key_hash is not None:
                                index = boot_record.find(pub_key_hash)
                                if index is not None:
                                    tlv_value = boot_record[0:index] + b'\0'*len(pub_key_hash) + boot_record[index+len(pub_key_hash):len(boot_record)]
                        else:
                            tlv_value = b[tlv_off:end_tlv]
                        outbinary += tlv_value
                        tlv_off=end_tlv
                    tlv_off = header_size+img_size+ ptlvs
                    tlv_info=b[tlv_off:tlv_off+TLV_SIZE]
                    magic_tlv, tlv_len_size = struct.unpack('HH', tlv_info) 
                if magic_tlv==TLV_INFO_MAGIC:
                    outbinary += tlv_info
                    end_tlv_np = tlv_off + tlv_len_size-TLV_INFO_SIZE
                    tlv_off+=TLV_SIZE
                    while tlv_off < end_tlv_np:
                        tlv_info = b[tlv_off:tlv_off+TLV_SIZE]
                        tlv_type, tlv_len = struct.unpack('HH', tlv_info)
                        end_tlv=tlv_off+tlv_len+TLV_SIZE
                        if tlv_type == TLV_VALUES['SHA256']  or (tlv_type == TLV_VALUES['KEYHASH'] and image_type == 1):
                            begin_position=tlv_off+TLV_SIZE
                            tlv_value = b[tlv_off:begin_position] + val_cleaned
                        elif tlv_type == TLV_VALUES['SHA384']:
                            val_cleaned=b'\0'*48
                            pubkey_cleaned=b'\0'*120
                            offset_key_size = 16
                            begin_position=tlv_off+TLV_SIZE
                            tlv_value = b[tlv_off:begin_position] + val_cleaned
                        elif tlv_type == TLV_VALUES['ECDSASIG']:
                            r_position=tlv_off+TLV_SIZE+5
                            s_position=r_position+32+3+offset_key_size
                            tlv_value = b[tlv_off:r_position] + val_cleaned+b[r_position+32+offset_key_size:s_position]+val_cleaned
                        elif tlv_type == TLV_VALUES['PUBKEY'] and image_type==2:
                            begin_position=tlv_off+TLV_SIZE
                            tlv_value = b[tlv_off:begin_position]+pubkey_cleaned
                        elif tlv_type == TLV_VALUES['ENCEC256']:
                            begin_position=tlv_off+TLV_SIZE+1
                            tlv_value = b[tlv_off:begin_position]+b'\0'*112
                        else:
                            tlv_value = b[tlv_off:end_tlv] + val_cleaned
                        outbinary += tlv_value
                        tlv_off=end_tlv
                outbinary=header+outbinary+b[tlv_off:]
            else:
                outbinary=header+b[offset:]
        if img_size != len(binary):
            print("file not substituable "+str(len(binary))+" "+str(img_size))
            return None
        return outbinary
    

    def _swap_bytes_in_blocks(self, data, block_size):
        """
        Swap bytes within each block of the given data.

        This function takes a byte array and a block size, and swaps the bytes
        within each block of the specified size. For example, if the block size
        is 4 and the data is [1, 2, 3, 4, 5, 6, 7, 8], the function will return
        [4, 3, 2, 1, 8, 7, 6, 5].

        Args:
            data (bytearray): The input data to be processed.
            block_size (int): The size of each block within which bytes will be swapped.

        Returns:
            bytearray: The data with bytes swapped within each block.
        """
        swapped_data = bytearray()
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            swapped_data.extend(block[::-1])
        return swapped_data
