#!/bin/bash

set -e

genCerts () {

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
		subj="/C=FR/ST=none/L=none/O=none/OU=none/CN=none"
		openssl req -new -x509 -sha256 -key $key -out $cert -days 3650 -subj $subj
	fi
}

firstParameter=$1
firstChar=${firstParameter:0:1}
if [ "$firstChar" = "-" ] || [ "$firstParameter" = "/opt/gfa/gfa" ]; then
	genCerts
	exec /opt/gfa/gfa "$@"
fi

exec "$@"
