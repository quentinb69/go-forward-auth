#!/bin/bash

set -e
APP_NAME=gfa
WORKING_DIR=/opt/${APP_NAME}
SSL_FOLDER=${WORKING_DIR}/ssl

# Generate private key and cert if they do not exist
generateCertificates () {

	# folder used for key storage
	key=${SSL_FOLDER}/server.key
	cert=${SSL_FOLDER}/server.crt

	if [ ! -f $key ];
	then
		echo "Generating ${key}..."
		mkdir -p $SSL_FOLDER
		openssl genrsa -out $key 2048 2> /dev/null
		openssl ecparam -genkey -name secp384r1 -out $key
	fi
	
	if [ ! -f $cert ];
	then
		echo "Generating ${cert}..."
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
if [ "$firstChar" = "-" ] || [ "$firstParameter" = "${WORGING_DIR}/${APP_NAME}" ]; then
	generateCertificates
	exec ${WORGING_DIR}/${APP_NAME} "$@"
fi

# if nor arguments and not gfa, launch 1st parameter passed to docker (bash for instance)
exec "$@"
