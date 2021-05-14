#!/bin/bash
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
ENCRYPTOR_DIR=../publish
if [[ $1 == "--help" ]]; then
	echo "first parameter --d for decryption , --e for encryption"
	echo "second parameter Input directory"
	echo "third parameter Key File (Private key for decryption, Public key for encryption)"
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
	#echo "Decrypting private key..."
	#TEMP_UNENCRYPTED_FILE=temp.pem
	#openssl rsa -in $2 -outform PEM -out $TEMP_UNENCRYPTED_FILE
	#if [ ! -f $TEMP_UNENCRYPTED_FILE ]; then
        #	echo "Private key file could not be unencrypted"
        #	exit
	#fi
	#keytouse=$TEMP_UNENCRYPTED_FILE
	#echo $keytouse
	echo "Enter password for Private key: "
	stty -echo		
	read s
	stty echo
	pvkeypasswd=$s
fi 
for fl in `ls -p $1/*.enc | grep -v '/$'`; do
	echo "Decrypting $fl"
	outfile=`echo $fl | awk -F '.' '{ print "."$NF }'`
	out=`echo $fl | sed "s/$outfile//"`
	echo "out $out"
	echo "$keytouse"
	if [ \( "$ans" = 'Y' \) -o \( "$ans" = 'y' \) ]; then 
		$ENCRYPTOR_DIR/Encryptor --d --k $keytouse --privatekeypassword $pvkeypasswd --i $fl --o $out
	else
		echo "key is not decrypted"	
		$ENCRYPTOR_DIR/Encryptor --d --k $keytouse --i $fl --o $out
	fi	
done
if [ -f $TEMP_UNENCRYPTED_FILE ]; then
	rm -rf $TEMP_UNENCRYPTED_FILE
fi
IFS=$SAVEIFS
