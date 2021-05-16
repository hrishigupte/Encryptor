#!/bin/bash
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
ENCRYPTOR_DIR=../publish
if [[ $1 == "--help" ]]; then
	echo "first paramter Input directory"
	echo "second parameter Key File (Private key for decryption, Public key for encryption)"
fi
if [$1 -eq ""]; then
	echo "Input directory not provided"
	exit
fi
if [ ! -d $1 ]; then
	echo "Input directory does not exist"
	exit
fi
if [$2 -eq ""]; then
	echo "Private key file not provided"
	exit
fi
if [ ! -f $2 ]; then
	echo "Private key does not exist"
fi
keytouse=$2
$pvkeypasswd=" " 
echo "Folder Name: $1"
echo "Private key file : $2"
echo "This process will decrypt files in the source folder...Is the private key encrypted? (Y/N)"
read ans
if [ \( "$ans" = 'Y' \) -o \( "$ans" = 'y' \) ]; then
	echo "Enter password for Private key: "
	stty -echo		
	read s
	stty echo
	pvkeypasswd=$s
fi

binsearchfiles="*enc"
#binsearchfiles="$1/*.enc"
base64searchfiles="*base64"

searchfiles="$1/$binsearchfiles"

base64input=0
bininput=0
base64pref=0

lastchar=$(echo ${1: -1})
#echo $lastchar

if [ $(find $1 -name $base64searchfiles -print 2>/dev/null) ]; then
	echo "found base64 files"
	base64input=1
fi
if [ $(find $1 -name $binsearchfiles -print 2>/dev/null) ]; then
	echo "Binary encrypted files found"
	bininput=1
fi

if [ $bininput -eq 0 ] && [ $base64input -eq 1 ]; then
	if [ $lastchar = "/" ]; then
		searchfiles="$1$base64searchfiles"
	else 
		searchfiles="$1/$base64searchfiles"
	fi
else
	if [ $lastchar = "/" ]; then
		searchfiles="$1$binsearchfiles"
	fi
fi
echo "Search file $searchfiles"

#for fl in `ls -p $1/*.enc | grep -v '/$'`; do
for fl in `ls -p $searchfiles | grep -v '/$'`; do
	echo "Decrypting $fl"
	#outfile=`echo $fl | awk -F '.' '{ print "."$NF }'`
	outfile=".enc"
	if [ $bininput -eq 0 ] && [ $base64input -eq 1 ]; then
		outfile=".enc.base64"
	 	base64pref=1		
	fi
	out=`echo $fl | sed "s/$outfile//"`
	echo "out $out"
	echo "$keytouse"
	if [ \( "$ans" = 'Y' \) -o \( "$ans" = 'y' \) ]; then
		if [ $base64pref -eq 1 ]; then
			$ENCRYPTOR_DIR/Encryptor --d --k $keytouse --base64 --privatekeypassword $pvkeypasswd --i $fl --o $out
		else
			$ENCRYPTOR_DIR/Encryptor --d --k $keytouse --privatekeypassword $pvkeypasswd --i $fl --o $out
		fi
	else
		echo "key is not encrypted"
		if [ $base64pref -eq 1 ]; then
			$ENCRYPTOR_DIR/Encryptor --d --k $keytouse --base64 --i $fl --o $out
		else	
			$ENCRYPTOR_DIR/Encryptor --d --k $keytouse --i $fl --o $out
		fi
	fi	
done
if [ -f $TEMP_UNENCRYPTED_FILE ]; then
	rm -rf $TEMP_UNENCRYPTED_FILE
fi
IFS=$SAVEIFS
