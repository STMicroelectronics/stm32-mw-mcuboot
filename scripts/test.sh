#!/bin/bash - 
# Absolute path to this script
SCRIPT=$(readlink -f $0)
# Absolute path this script
projectdir=`dirname $SCRIPT`

secure_bin=$projectdir"/Project.bin"
non_secure_bin=$projectdir"/Project.bin"
secure_sign_bin=$projectdir"/tfm_signed_s.bin"
non_secure_sign_bin=$projectdir"/tfm_signed_ns.bin"
secure_encsign_bin=$projectdir"/tfm_enc_signed_s.bin"
non_secure_encsign_bin=$projectdir"/tfm_enc_signed_ns.bin"
#path working
ECC_KEY_FILE_S=$projectdir"/root-ec-p256.pem"
RSA_KEY_FILE_S=$projectdir"/root-rsa-3072.pem"
ECC_ENC_KEY_PRIV=$projectdir"/enc-ec256-priv.pem"
ECC_ENC_KEY_PUB=$projectdir"/enc-ec256-pub.pem"
AES_KW_ENC_KEY=$projectdir"/aes-kw-128.b64"
ECC_KEY_FILE_S=$projectdir"/root-ec-p256.pem"
ECC_KEY_FILE_NS=$projectdir"/root-ec-p256_1.pem"
RSA_ENC_KEY_PRIV=$projectdir"/enc-rsa2048-priv.pem"
RSA_ENC_KEY_PUB=$projectdir"/enc-rsa2048-pub.pem"
RSA_KEY_FILE_NS=$projectdir"/root-rsa-3072_1.pem"

#imgtool="python "$projectdir"/imgtool.py"
imgtool=$projectdir"/dist/imgtool/imgtool"

ENCRYPT_RSA=0
ENCRYPT_ECC=1
GENKEY=0
image_ns_size=0x8000
image_s_size=0x2c000

if [ $ENCRYPT_RSA != 0 ]; then
KEY_FILE_S=$RSA_KEY_FILE_S
KEY_FILE_NS=$RSA_KEY_FILE_NS
ENC_KEY_PUB=$RSA_ENC_KEY_PUB
fi
if [ $ENCRYPT_ECC != 0 ]; then

KEY_FILE_S=$ECC_KEY_FILE_S
KEY_FILE_NS=$ECC_KEY_FILE_NS
ENC_KEY_PUB=$ECC_ENC_KEY_PUB
fi

if [ $GENKEY != 0 ]; then
	COMMAND="$imgtool keygen -k "$KEY_FILE_S" -t ecdsa-p256
	echo $COMMAND
	$COMMAND
	ret=$?
	if [ $ret != 0 ]; then
	echo "secure key generation failed"
	exit 1
	fi
	COMMAND="$imgtool keygen -k "$KEY_FILE_NS" -t ecdsa-p256
	echo $COMMAND
	$COMMAND
	ret=$?
	if [ $ret != 0 ]; then
	echo "secure key generation failed"
	exit 1
	fi
fi
SIGN_ONLY=0
if [ $SIGN_ONLY != 0 ]; then
# S slot size
# H header size
# --pad pad image to slot size
#
COMMAND="$imgtool sign -k "$KEY_FILE_S"  -e little -S $image_s_size -H 0x400 --pad-header --pad --overwrite-only -v 0.0.0 -s auto --boot-record SPE --align 8 "$secure_bin" "$secure_sign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "secure sign failed"
exit 1
fi
COMMAND="$imgtool sign -k "$KEY_FILE_NS"  -e little -S $image_ns_size -H 0x400 --pad-header --pad --overwrite-only -v 0.0.0  -s auto --boot-record NSPE --align 8  "$non_secure_bin" "$non_secure_sign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "non secure sign failed"
exit 1
fi
fi

#COMMAND="imgtool verify -k "$RSA_KEY_FILE_S"  "$secure_sign_bin
#echo $COMMAND
#$COMMAND
#ret=$?
#if [ $ret != 0 ]; then
#echo "verify sign failed"
#exit 1
#fi
COMMAND="$imgtool sign -k "$KEY_FILE_S" -o 0x9000000 -E "$ENC_KEY_PUB"  -e little -S $image_s_size -H 0x400 --pad-header --pad --overwrite-only -v 0.0.0  -s auto --boot-record SPE  --align 8 "$secure_bin" "$secure_encsign_bin
#COMMAND="python $imgtool sign -k "$KEY_FILE_S"   -e little -S $image_s_size -H 0x400 --pad-header --pad --overwrite-only -v 0.0.0  -s auto --boot-record SPE  --align 8 "$secure_bin" "$secure_encsign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "sign secure failed"
exit 1
fi
COMMAND="$imgtool  verify -k "$KEY_FILE_S"  "$secure_encsign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "verify enc sign failed"
exit 1
fi
COMMAND="$imgtool sign -k "$KEY_FILE_NS"  -E "$ENC_KEY_PUB" -e little -S $image_ns_size -H 0x400 --pad-header --pad  -v 0.0.0  -s auto --boot-record NSPE --align 8 --primary-only  "$non_secure_bin" "$non_secure_encsign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "sign non secure failed"
exit 1
fi	
COMMAND="$imgtool  verify -k "$KEY_FILE_NS"  "$non_secure_encsign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "verify enc sign primary only failed"
exit 1
fi

COMMAND="$imgtool sign -k "$KEY_FILE_NS"  -E "$ENC_KEY_PUB" -e little -S $image_ns_size -H 0x400 --pad-header --pad  -v 0.0.0  -s auto --boot-record NSPE --align 8 "$non_secure_bin" "$non_secure_encsign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "sign non secure failed"
exit 1
fi	
COMMAND="$imgtool  verify -k "$KEY_FILE_NS"  "$non_secure_encsign_bin
echo $COMMAND
$COMMAND
ret=$?
if [ $ret != 0 ]; then
echo "verify enc sign failed"
exit 1
fi	
