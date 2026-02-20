

"""
ECDSA key management
"""
# Copyright 2020-2026 STMicroelectronics
# SPDX-License-Identifier: Apache-2.0
import os.path
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import Hash,SHA256, SHA384
from cryptography.hazmat.primitives.asymmetric import utils
from .general import KeyClass
from .privatebytes import PrivateBytesMixin


class ECDSAUsageError(Exception):
    pass


class ECDSAPublicKey(KeyClass):
    """
    Wrapper around an ECDSA public key.
    """
    def __init__(self, key, extension="", priv=""):
        self.key = key
        self.extension=extension
        self.privname=priv
    def key_size(self):
        return self.key.key_size

    def shortname(self):
        return "ecdsa"

    def ext(self):
        return self.extension
 
    def name(self):
        return self.privname

    def _unsupported(self, name):
        raise ECDSAUsageError("Operation {} requires private key".format(name))

    def _get_public(self):
        return self.key

    def get_public_bytes(self):
        # The key is embedded into MBUboot in "SubjectPublicKeyInfo" format
        return self._get_public().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    def get_public_bytes_raw(self):
        pn=  self._get_public().public_numbers()
        public_bytes = pn.x.to_bytes(32, byteorder='big') + pn.y.to_bytes(32, byteorder='big')
        return public_bytes

    def get_public_pem(self):
        return self._get_public().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def get_private_bytes(self, minimal, format):
        self._unsupported('get_private_bytes')

    def export_private(self, path, passwd=None):
        self._unsupported('export_private')

    def export_public(self, path):
        """Write the public key to the given file."""
        pem = self._get_public().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(path, 'wb') as f:
            f.write(pem)


class ECDSAPrivateKey(PrivateBytesMixin):
    """
    Wrapper around an ECDSA private key.
    """
    def __init__(self, key):
        self.key = key

    def _get_public(self):
        return self.key.public_key()

    def _build_minimal_ecdsa_privkey(self, der, format):
        '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''

        if format == serialization.PrivateFormat.OpenSSH:
            print(os.path.basename(__file__) +
                  ': Warning: --minimal is supported only for PKCS8 '
                  'or TraditionalOpenSSL formats')
            return bytearray(der)

        EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
        if format == serialization.PrivateFormat.PKCS8:
            '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''
            offset_PUB = 68
            EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
            if der[offset_PUB] != 0xa1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1]
            b = bytearray(der[:-offset_PUB])
            offset_SEQ = 29
            if b[offset_SEQ] != 0x30:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[offset_SEQ + 1] -= len_PUB
            offset_OCT_STR = 27
            if b[offset_OCT_STR] != 0x04:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[offset_OCT_STR + 1] -= len_PUB
            if b[0] != 0x30 or b[1] != 0x81:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[2] -= len_PUB
            

        elif format == serialization.PrivateFormat.TraditionalOpenSSL:
            offset_PUB = 51
            if der[offset_PUB] != 0xA1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1] + 2
            b = bytearray(der[0:offset_PUB])
            b[1] -= len_PUB

        return b


    _VALID_FORMATS = {
        'pkcs8': serialization.PrivateFormat.PKCS8,
        'openssl': serialization.PrivateFormat.TraditionalOpenSSL
    }
    _DEFAULT_FORMAT = 'pkcs8'

    def get_private_bytes(self, minimal, format):
        format, priv = self._get_private_bytes(minimal,
                                               format, ECDSAUsageError)
        if minimal:
            priv = self._build_minimal_ecdsa_privkey(
                priv, self._VALID_FORMATS[format])
        return priv

    def export_private(self, path, passwd=None):
        """Write the private key to the given file, protecting it with '
          'the optional password."""
        if passwd is None:
            enc = serialization.NoEncryption()
        else:
            enc = serialization.BestAvailableEncryption(passwd)
        pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc)
        with open(path, 'wb') as f:
            f.write(pem)


class ECDSA256P1Public(ECDSAPublicKey):
    """
    Wrapper around an ECDSA (p256) public key.
    """
    def __init__(self, key, extension="", priv=""):
        super().__init__(key, extension, priv)
        self.key = key

    def shortname(self):
        return "ecdsa"

    def sig_type(self):
        return "ECDSA256_SHA256"

    def sig_tlv(self):
        return "ECDSASIG"

    def sig_len(self):
        # Early versions of MCUboot (< v1.5.0) required ECDSA
        # signatures to be padded to 72 bytes.  Because the DER
        # encoding is done with signed integers, the size of the
        # signature will vary depending on whether the high bit is set
        # in each value.  This padding was done in a
        # not-easily-reversible way (by just adding zeros).
        #
        # The signing code no longer requires this padding, and newer
        # versions of MCUboot don't require it.  But, continue to
        # return the total length so that the padding can be done if
        # requested.
        return 72
 
    def _build_compress_signature(self, der):
        # DER format is
        # 0 :ASN1 header (0x30)
        # 1 :len
        # 2 :tag (0x2)
        # 3 :len R signature (including zero data)
        # 4 :Zero data (0x0)
        # 5 :R signature
        # 4+ len R signature :tag (0x2)
        # 4+ len R signature +1 :len S signature (including zero data)
        # 4+ len R signature +2 :Zero data
        # 4+ len R signature +3 :S signature
        # len of complete area
        offset_LEN=1
        # offset of length for R signature
        offset_LEN_R=3
        offset_LEN_S=der[offset_LEN_R]+5
        legend="Transform signature to be verify to "
        if der[offset_LEN] == 0x46 :
           # check that null bytes are present with first value > 127 , in this case
           # 0 is not set because R and S are signed, 0 is set only to indicate that last
           # S is negative , else signature verification not working
           if  der[offset_LEN_R +1]== 0x0 and der[offset_LEN_R +2] > 127 and der[offset_LEN_S +1]== 0x0 and der[offset_LEN_S +2] > 127:
            b = der[0:offset_LEN]
            b += bytes([0x46, 2, 33]) + der[offset_LEN_R+1:offset_LEN_S-1]
            b += bytes([2, 33])+ der[offset_LEN_S+1:der[offset_LEN]+2]
            return b
           elif  der[offset_LEN_R +1]== 0x0 and der[offset_LEN_R +2] < 128 and der[offset_LEN_S +1]== 0x0 and der[offset_LEN_S +2] < 128:
            b = der[0:offset_LEN]
            b += bytes([0x44, 2, 32]) + der[offset_LEN_R+2:offset_LEN_S-1]
            b += bytes([2, 32])+ der[offset_LEN_S+2:der[offset_LEN]+2]
            return b
           elif der[offset_LEN_S +1]== 0x0 and der[offset_LEN_S +2] < 128:
            b = der[0:offset_LEN]
            b += bytes([0x45, 2, 33]) + der[offset_LEN_R+1:offset_LEN_S-1]
            b += bytes([2, 32])+ der[offset_LEN_S+2:der[offset_LEN]+2]
            return b
           else :
            b = der[0:offset_LEN]
            b += bytes([0x45, 2, 32]) + der[offset_LEN_R+2:offset_LEN_S-1]
            b += bytes([2, 33])+ der[offset_LEN_S+1:der[offset_LEN]+2]
            return b
        return der

    def _key_info_(self, der):
        offset_LEN=1
        offset_LEN_R=3
        if der[0] != 0x30:
            raise ValueError("Incorrect signature")
        else:
            # Signature size
            total_length = der[offset_LEN]
            
            # default initialization
            r_length = "not present"
            s_length = "not present"
            
            # extract and verify R
            if len(der) > 3 and der[2] == 0x02:
                r_length = der[3]
            
            # extract and verify S
            if len(der) > 5 + r_length and der[4 + r_length] == 0x02:
                s_length = der[5 + r_length]
            
            # display the result on the same line
            print(f"ECDSA size: 0x{total_length:02x}, R : ({hex(r_length)}), S: ({hex(s_length)})")           

    def verify(self, signature, payload, digest=None, header_size=None, img_size=None):
        self._key_info_(signature)
        # strip possible paddings added during sign
        signature=self._build_compress_signature(signature)
        # signature = signature[:signature[1] + 2]
        k = self.key
        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            k = self.key.public_key()
        # use digest instead of payload
        if digest is None:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(payload)
            digest = digest.finalize()
        return k.verify(bytes(signature), bytes(digest),ec.ECDSA(utils.Prehashed(SHA256())))


class ECDSA256P1(ECDSAPrivateKey, ECDSA256P1Public):
    """
    Wrapper around an ECDSA (p256) private key.
    """

    def __init__(self, key, extension="", priv=""):
        self.key = key
        self.extension=extension
        self.privname=priv
        self.pad_sig = False

    @staticmethod
    def generate():
        pk = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend())
        return ECDSA256P1(pk)

    def _get_private(self):
        return self.key

    def _get_public(self):
        return self.key.public_key()

    def _build_minimal_ecdsa_privkey(self, der, format):
        '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''

        if format == serialization.PrivateFormat.OpenSSH:
            print(os.path.basename(__file__) +
                  ': Warning: --minimal is supported only for PKCS8 '
                  'or TraditionalOpenSSL formats')
            return bytearray(der)

        EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
        if format == serialization.PrivateFormat.PKCS8:
            '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''
            offset_PUB = 68
            EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
            if der[offset_PUB] != 0xa1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1]
            b = bytearray(der[:-offset_PUB])
            offset_SEQ = 29
            if b[offset_SEQ] != 0x30:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[offset_SEQ + 1] -= len_PUB
            offset_OCT_STR = 27
            if b[offset_OCT_STR] != 0x04:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[offset_OCT_STR + 1] -= len_PUB
            if b[0] != 0x30 or b[1] != 0x81:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[2] -= len_PUB
            

        elif format == serialization.PrivateFormat.TraditionalOpenSSL:
            offset_PUB = 51
            if der[offset_PUB] != 0xA1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1] + 2
            b = bytearray(der[0:offset_PUB])
            b[1] -= len_PUB

        return b

    _VALID_FORMATS = {
        'pkcs8': serialization.PrivateFormat.PKCS8,
        'openssl': serialization.PrivateFormat.TraditionalOpenSSL
    }
    _DEFAULT_FORMAT = 'pkcs8'
    
    def build_uncompress_signature(self, der):
        # DER format is
        # 0 :ASN1 header (0x30)
        # 1 :len
        # 2 :tag (0x2)
        # 3 :len R signature (including zero data)
        # 4 :Zero data (0x0)
        # 5 :R signature
        # 4+ len R signature :tag (0x2)
        # 4+ len R signature +1 :len S signature (including zero data)
        # 4+ len R signature +2 :Zero data
        # 4+ len R signature +3 :S signature
        # len of complete area
        offset_LEN=1
        # offset of length for R signature
        offset_LEN_R=3
        offset_LEN_S=der[offset_LEN_R]+5
        if der[offset_LEN] != 0x46:
           byte_R_to_add =  0x21 - der[offset_LEN_R]
           byte_R_to_get =  der[offset_LEN_R]
           # get bytes up to tag
           b = bytearray(der[0:offset_LEN])
           b += bytes([70, 2, 33])+bytes(byte_R_to_add)
           # zero data must be taken
           b += bytearray(der[offset_LEN_R+1:offset_LEN_R+byte_R_to_get+1])
           byte_S_to_add = 0x21 - der[offset_LEN_S]
           byte_S_to_get = der[offset_LEN_S]
           # add tag and len
           b += bytes([2,33])
           b += bytes(byte_S_to_add)
           b += bytearray(der[offset_LEN_S+1:offset_LEN_S+byte_S_to_get+2])
           return b
        return der

    _VALID_FORMATS = {
        'pkcs8': serialization.PrivateFormat.PKCS8,
        'openssl': serialization.PrivateFormat.TraditionalOpenSSL
    }
    _DEFAULT_FORMAT = 'pkcs8'

    def get_private_bytes(self, minimal, format):
        format, priv = self._get_private_bytes(minimal,
                                               format, ECDSAUsageError)
        if minimal:
            priv = self._build_minimal_ecdsa_privkey(
                priv, self._VALID_FORMATS[format])
        return priv

    def export_private(self, path, passwd=None):
        """Write the private key to the given file, protecting it with the optional password."""
        if passwd is None:
            enc = serialization.NoEncryption()
        else:
            enc = serialization.BestAvailableEncryption(passwd)
        pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc)
        with open(path, 'wb') as f:
            f.write(pem)

    def raw_sign(self, payload):
        """Return the actual signature"""
        return self.key.sign(
                data=payload,
                signature_algorithm=ec.ECDSA(SHA256()))

    def sign(self, payload):
        for attempt in range(3):
            sig = self.raw_sign(payload)
            if self._check_signature_size(sig):
                if self.pad_sig:
                    sig = self.build_uncompress_signature(sig)
                return sig        
        raise ValueError("Signature size is not correct")
        

    def sign_digest(self, digest):
       chosen_hash = SHA256()
       for attempt in range(3):
            sig = self.key.sign(digest,ec.ECDSA(utils.Prehashed(chosen_hash)))
            if self._check_signature_size(sig):
                return sig
       raise ValueError("Signature size is not correct")

    def _check_signature_size(self,der):
        # check if size of R & S are 32 bytes(maximum), if not it could cause issue in signature padding.
        if der[0] != 0x30:
            return False
            # Signature size
        # default initialization
        r_length = "not present"
        s_length = "not present"
        
        # extract and verify R
        if len(der) > 3 and der[2] == 0x02:
            r_length = der[3]
        # extract and verify S
        if len(der) > 5 + r_length and der[4 + r_length] == 0x02:
            s_length = der[5 + r_length]
        if r_length < 0x20:
            return False
        if s_length < 0x20:
            return False
        return True 

class ECDSA384P1Public(ECDSAPublicKey):
    """
    Wrapper around an ECDSA (p384) public key.
    """
    def __init__(self, key, extension="", priv=""):
        super().__init__(key, extension, priv)
        self.key = key

    def shortname(self):
        return "ecdsap384"

    def sig_type(self):
        return "ECDSA384_SHA384"

    def sig_tlv(self):
        return "ECDSASIG"

    def sig_len(self):
        # Early versions of MCUboot (< v1.5.0) required ECDSA
        # signatures to be padded to a fixed length.  Because the DER
        # encoding is done with signed integers, the size of the
        # signature will vary depending on whether the high bit is set
        # in each value.  This padding was done in a
        # not-easily-reversible way (by just adding zeros).
        #
        # The signing code no longer requires this padding, and newer
        # versions of MCUboot don't require it.  But, continue to
        # return the total length so that the padding can be done if
        # requested.
        return 103

    def _build_compress_signature(self, der):
        # DER format is
        # 0 : ASN1 header (0x30)
        # 1 : len
        # 2 : tag (0x2)
        # 3 : len R signature (including zero data)
        # 4 : Zero data (0x0)
        # 5 : R signature
        # 4 + len R signature : tag (0x2)
        # 4 + len R signature + 1 : len S signature (including zero data)
        # 4 + len R signature + 2 : Zero data
        # 4 + len R signature + 3 : S signature
        # len of complete area
        offset_LEN = 1
        # offset of length for R signature
        offset_LEN_R = 3
        offset_LEN_S = der[offset_LEN_R] + 5
        legend = "Transform signature to be verify to "

        # Check that the length is correct for a DER-encoded ECDSA-384 signature
        if der[offset_LEN] == 0x66:  # Adjusted for SHA-384
            # Check that null bytes are present with first value > 127
            if der[offset_LEN_R + 1] == 0x0 and der[offset_LEN_R + 2] > 127 and der[offset_LEN_S + 1] == 0x0 and der[offset_LEN_S + 2] > 127:
                b = der[0:offset_LEN]
                b += bytes([0x66, 2, 49]) + der[offset_LEN_R + 1:offset_LEN_S - 1]
                b += bytes([2, 49]) + der[offset_LEN_S + 1:der[offset_LEN] + 2]
                return b
            elif der[offset_LEN_R + 1] == 0x0 and der[offset_LEN_R + 2] < 128 and der[offset_LEN_S + 1] == 0x0 and der[offset_LEN_S + 2] < 128:
                b = der[0:offset_LEN]
                b += bytes([0x64, 2, 48]) + der[offset_LEN_R + 2:offset_LEN_S - 1]
                b += bytes([2, 48]) + der[offset_LEN_S + 2:der[offset_LEN] + 2]
                return b
            elif der[offset_LEN_S + 1] == 0x0 and der[offset_LEN_S + 2] < 128:
                b = der[0:offset_LEN]
                b += bytes([0x65, 2, 49]) + der[offset_LEN_R + 1:offset_LEN_S - 1]
                b += bytes([2, 48]) + der[offset_LEN_S + 2:der[offset_LEN] + 2]
                return b
            else:
                b = der[0:offset_LEN]
                b += bytes([0x65, 2, 48]) + der[offset_LEN_R + 2:offset_LEN_S - 1]
                b += bytes([2, 49]) + der[offset_LEN_S + 1:der[offset_LEN] + 2]
                return b
        return der


    def _key_info_(self, der):
        offset_LEN = 1
        offset_LEN_R = 3

        # Check that the first byte is the ASN.1 header (0x30)
        if der[0] != 0x30:
            raise ValueError("Incorrect signature")
        else:
            # Total size of the signature
            total_length = der[offset_LEN]

            # Default initialization
            r_length = "not present"
            s_length = "not present"

            # Extract and check R
            if len(der) > 3 and der[2] == 0x02:
                r_length = der[3]

            # Extract and check S
            if len(der) > 5 + r_length and der[4 + r_length] == 0x02:
                s_length = der[5 + r_length]

            print(f"ECDSA size: 0x{total_length:02x}, R: ({hex(r_length)}), S: ({hex(s_length)})")


    def verify(self, signature, payload, digest=None, header_size=None, img_size=None):
        self._key_info_(signature)
        # strip possible paddings added during sign
        signature = self._build_compress_signature(signature)
        #signature = signature[:signature[1] + 2]
        k = self.key
        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            k = self.key.public_key()
        # use digest instead of payload
        if digest is None:
           digest = hashes.Hash(hashes.SHA384())
           digest.update(payload)
           digest = digest.finalize()
        return k.verify(bytes(signature), bytes(digest),
                        signature_algorithm=ec.ECDSA(utils.Prehashed(SHA384())))

    def emit_c_public_hash(self, file=sys.stdout):
        digest = Hash(SHA384())
        digest.update(self.get_public_bytes())
        self._emit(
                header="const unsigned char {}_pub_key_hash[] = {{"
                       .format(self.shortname()),
                trailer="};",
                encoded_bytes=digest.finalize(),
                indent="    ",
                len_format="const unsigned int {}_pub_key_hash_len = {{}};"
                           .format(self.shortname()),
                file=file)

    def emit_raw_public_hash(self, file=sys.stdout):
        digest = Hash(SHA384())
        digest.update(self.get_public_bytes())
        self._emit_raw(digest.finalize(), file=file)

    def emit_public_bin(self, sha, raw, file=sys.stdout):
        if raw:
            value=self.get_public_bytes_raw()
        else:
            value=self.get_public_bytes()
        if sha:
            digest = Hash(SHA384())
            digest.update(value)
            value = digest.finalize()
        sys.stdout.buffer.write(bytes(value))
    
    def get_public_bytes_raw(self):
        pn=  self._get_public().public_numbers()
        public_bytes = pn.x.to_bytes(48, byteorder='big') + pn.y.to_bytes(48, byteorder='big')
        return public_bytes

class ECDSA384P1(ECDSAPrivateKey, ECDSA384P1Public):
    """
    Wrapper around an ECDSA (p384) private key.
    """

    def __init__(self, key, extension="", priv=""):
        self.key = key
        self.extension=extension
        self.privname=priv
        self.pad_sig = False

    @staticmethod
    def generate():
        pk = ec.generate_private_key(
                ec.SECP384R1(),
                backend=default_backend())
        return ECDSA384P1(pk)


    def raw_sign(self, payload):
        """Return the actual signature"""
        return self.key.sign(
                data=payload,
                signature_algorithm=ec.ECDSA(SHA384()))

    def build_uncompress_signature(self, der):
        # DER format is
        # 0 : ASN1 header (0x30)
        # 1 : len
        # 2 : tag (0x2)
        # 3 : len R signature (including zero data)
        # 4 : Zero data (0x0)
        # 5 : R signature
        # 4 + len R signature : tag (0x2)
        # 4 + len R signature + 1 : len S signature (including zero data)
        # 4 + len R signature + 2 : Zero data
        # 4 + len R signature + 3 : S signature
        # len of complete area
        offset_LEN = 1
        # offset of length for R signature
        offset_LEN_R = 3
        offset_LEN_S = der[offset_LEN_R] + 5

        if der[offset_LEN] != 0x66:  # Adjusted for SHA-384
            byte_R_to_add = 0x31 - der[offset_LEN_R]
            byte_R_to_get = der[offset_LEN_R]
            # get bytes up to tag
            b = bytearray(der[0:offset_LEN])
            b += bytes([0x66, 2, 49]) + bytes([0] * byte_R_to_add)
            # zero data must be taken
            b += bytearray(der[offset_LEN_R + 1:offset_LEN_R + byte_R_to_get + 1])
            byte_S_to_add = 0x31 - der[offset_LEN_S]
            byte_S_to_get = der[offset_LEN_S]
            # add tag and len
            b += bytes([2, 49]) + bytes([0] * byte_S_to_add)
            b += bytearray(der[offset_LEN_S + 1:offset_LEN_S + byte_S_to_get + 2])
            return b
        return der

    def sign(self, payload):
        for attempt in range(3):
            sig = self.raw_sign(payload)
            if self._check_signature_size(sig):
                if self.pad_sig:
                    sig = self.build_uncompress_signature(sig)
                return sig        
        raise ValueError("Signature size is not correct")

    def sign_digest(self, digest):
        chosen_hash = SHA384()
        for attempt in range(3):
            sig = self.key.sign(digest,ec.ECDSA(utils.Prehashed(chosen_hash)))
            if self._check_signature_size(sig):
                return sig        
        raise ValueError("Signature size is not correct")
      

    def _check_signature_size(self,der):
        # check if size of R & S are 48 bytes(maximum), if not it could cause issue in signature padding.
        if der[0] != 0x30:
            return False
            # Signature size
        # default initialization
        r_length = "not present"
        s_length = "not present"
        
        # extract and verify R
        if len(der) > 3 and der[2] == 0x02:
            r_length = der[3]
        # extract and verify S
        if len(der) > 5 + r_length and der[4 + r_length] == 0x02:
            s_length = der[5 + r_length]
        if r_length < 0x30:
            return False
        if s_length < 0x30:
            return False
        return True 
    
    def _build_minimal_ecdsa_privkey(self, der, format):
        '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''

        if format == serialization.PrivateFormat.OpenSSH:
            print(os.path.basename(__file__) +
                  ': Warning: --minimal is supported only for PKCS8 '
                  'or TraditionalOpenSSL formats')
            return bytearray(der)

        EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
        if format == serialization.PrivateFormat.PKCS8:
            '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''
            offset_PUB = 83
            EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
            if der[offset_PUB] != 0xa1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1]
            b = bytearray(der[:-offset_PUB])
            offset_SEQ = 27
            if b[offset_SEQ] != 0x30:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[offset_SEQ + 2] -= len_PUB
            offset_OCT_STR = 24
            if b[offset_OCT_STR] != 0x04:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[offset_OCT_STR + 1] -= len_PUB
            if b[0] != 0x30 or b[1] != 0x81:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            b[2] -= len_PUB
            

        elif format == serialization.PrivateFormat.TraditionalOpenSSL:
            offset_PUB = 51
            if der[offset_PUB] != 0xA1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1] + 2
            b = bytearray(der[0:offset_PUB])
            b[1] -= len_PUB

        return b
   
    _VALID_FORMATS = {
    'pkcs8': serialization.PrivateFormat.PKCS8,
    'openssl': serialization.PrivateFormat.TraditionalOpenSSL
    }

    def get_private_bytes(self, minimal, format):
        format, priv = self._get_private_bytes(minimal,
                                               format, ECDSAUsageError)
        if minimal:
            priv = self._build_minimal_ecdsa_privkey(
                priv, self._VALID_FORMATS[format])
        return priv

    def export_private(self, path, passwd=None):
        """Write the private key to the given file, protecting it with the optional password."""
        if passwd is None:
            enc = serialization.NoEncryption()
        else:
            enc = serialization.BestAvailableEncryption(passwd)
        pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc)
        with open(path, 'wb') as f:
            f.write(pem)
    
    def emit_private(self, minimal, format,raw, file=sys.stdout):
         if self.shortname()=="sym":
            self._emit(
                header="const unsigned char {}_value[] = {{".format(self.name()),
                trailer="};",
                encoded_bytes=self.get_private_bytes(minimal,format),
                indent="    ",
                len_format="const unsigned int {}_len = {{}};".format(self.name()),
                file=file)

         else:
            value=self.get_private_bytes(minimal,format)
            if "initial_attestation" in self.name() or raw:
               value=value[36:84]
            self._emit(
                header="const unsigned char {}_priv_key[] = {{".format(self.name()),
                trailer="};",
                encoded_bytes=value,
                indent="    ",
                len_format="const unsigned int {}_priv_key_len = {{}};".format(self.name()),
                file=file)


    def emit_private_bin(self, minimal,raw, file=sys.stdout):
        value=self.get_private_bytes(minimal,None)
        if "initial_attestation" in self.name() or raw:
            value=value[36:84] 
        sys.stdout.buffer.write(bytes(value))


class ECDSA256P1_SSL(ECDSAPrivateKey,ECDSA256P1Public):
    """
    Wrapper around an ECDSA private key.
    """

    def __init__(self, key, extension="", priv=""):
        """key should be an instance of EllipticCurvePrivateKey"""
        self.key = key
        self.pad_sig = False
        self.extension=extension
        self.privname=priv
    @staticmethod
    def generate():
        pk = ec.generate_private_key(
                ec.SECP256R1(),
                backend=default_backend())
        return ECDSA256P1_SSL(pk)

    def _get_public(self):
        return self.key.public_key()

    def _build_minimal_ecdsa_privkey(self, der, format):
        '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''

        if format == serialization.PrivateFormat.OpenSSH:
            print(os.path.basename(__file__) +
                  ': Warning: --minimal is supported only for PKCS8 '
                  'or TraditionalOpenSSL formats')
            return bytearray(der)

        EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
        if format == serialization.PrivateFormat.PKCS8:
           '''
        Builds a new DER that only includes the EC private key, removing the
        public key that is added as an "optional" BITSTRING.
        '''
           offset_PUB = 68
           EXCEPTION_TEXT = "Error parsing ecdsa key. Please submit an issue!"
           if der[offset_PUB] != 0xa1:
               raise ECDSAUsageError(EXCEPTION_TEXT)
           len_PUB = der[offset_PUB + 1]
           b = bytearray(der[:-offset_PUB])
           offset_SEQ = 29
           if b[offset_SEQ] != 0x30:
               raise ECDSAUsageError(EXCEPTION_TEXT)
           b[offset_SEQ + 1] -= len_PUB
           offset_OCT_STR = 27
           if b[offset_OCT_STR] != 0x04:
               raise ECDSAUsageError(EXCEPTION_TEXT)
           b[offset_OCT_STR + 1] -= len_PUB
           if b[0] != 0x30 or b[1] != 0x81:
               raise ECDSAUsageError(EXCEPTION_TEXT)
           b[2] -= len_PUB
            

        elif format == serialization.PrivateFormat.TraditionalOpenSSL:
            offset_PUB = 51
            if der[offset_PUB] != 0xA1:
                raise ECDSAUsageError(EXCEPTION_TEXT)
            len_PUB = der[offset_PUB + 1] + 2
            b = bytearray(der[0:offset_PUB])
            b[1] -= len_PUB

        return b

    _VALID_FORMATS = {
        'pkcs8': serialization.PrivateFormat.PKCS8,
        'openssl': serialization.PrivateFormat.TraditionalOpenSSL
    }
    _DEFAULT_FORMAT = 'openssl'

   

    def get_private_bytes(self, minimal, format):
        format, priv = self._get_private_bytes(minimal,
                                               format, ECDSAUsageError)
        if minimal:
            priv = self._build_minimal_ecdsa_privkey(
                priv, self._VALID_FORMATS[format])
        return priv

    def export_private(self, path, passwd=None):
        """Write the private key to the given file, protecting it with the optional password."""
        if passwd is None:
            enc = serialization.NoEncryption()
        else:
            enc = serialization.BestAvailableEncryption(passwd)
        pem = self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=enc)
        with open(path, 'wb') as f:
            f.write(pem)

    def raw_sign(self, payload):
        """Return the actual signature"""
        return self.key.sign(
                data=payload,
                signature_algorithm=ec.ECDSA(SHA256()))

    def sign(self, payload):
        sig = self.raw_sign(payload)
        if self.pad_sig:
            # To make fixed length, pad with one or two zeros.
            sig += b'\000' * (self.sig_len() - len(sig))
            return sig
        else:
            return sig
