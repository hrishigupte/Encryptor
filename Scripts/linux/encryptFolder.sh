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
	echo "Public key file not provided"
	exit
fi
if [ ! -f $2 ]; then
	echo "Public key does not exist"
fi
echo "Folder Name: $1"
echo "Public key file : $2"
echo "This process will encrypt files in the source folder...Do you want to proceed? (Y/N)"
read ans
if [ \( "$ans" = 'N' \) -o \( "$ans" = 'n' \) ]; then
	echo "Exiting..."
	exit
fi 
for fl in `ls -p $1 | grep -v '/$'`; do
	echo "Encrypting $fl"
	$ENCRYPTOR_DIR/Encryptor --e --k $2 --i $1/$fl --o $1/$fl.enc	
	echo "Output $fl.enc"
	
done
IFS=$SAVEIFS
