#!/bin/bash

set -e

# Generate private key and cert if they do not exist
genCerts () {

	# folder used for key storage
	folder=/opt/gfa/ssl
	key=$folder/server.key
	cert=$folder/server.crt

	if [ ! -f $key ];
	then
		echo "Generating private key"
		mkdir -p $folder
		openssl genrsa -out $key 2048
		openssl ecparam -genkey -name secp384r1 -out $key
	fi
	
	if [ ! -f $cert ];
	then
		echo "Generating certificate"
		# self signed cert so no real subj
		subj="/C=FR/ST=none/L=none/O=GFA/OU=none/CN=none"
		openssl req -new -x509 -sha256 -key $key -out $cert -days 3650 -subj $subj
	fi
}

# extract first parameter and first char of fist parameter
firstParameter=$1
firstChar=${firstParameter:0:1}
# if first char is an argument (start with "-") 
# OR first parameter is the executable "gfa"
# THEN generate certificates and start GFA
if [ "$firstChar" = "-" ] || [ "$firstParameter" = "/opt/gfa/gfa" ]; then
	genCerts
	exec /opt/gfa/gfa "$@"
fi

# if nor arguments and not gfa, launch 1st parameter passed to docker (bash for instance)
exec "$@"
