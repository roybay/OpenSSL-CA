#!/bin/bash

. ./pki.properties

PRG=$0
TYPE=$1
CERTNAME=$2

usage(){
	clear
	echo "usage:$PRG ..." >&2
	echo -e "\t./pki-script [type] [Common Name]"
	echo -e "\t\tType: user, server, revokeCert, revokeAuth, verify\n"
	echo -e "\t\tEx: ./pki-scripts user rbahian_tst\n"

	echo -e "\t./pki-script [type]"
	echo -e "\t\tType: arl, crl, init\n"
	echo -e "\t\tEx: ./pki-scripts arl"
	echo -e "\t\tIf OpenSSL folder is exist, ignore the initial configuration (init)\n"

}

function init_dir(){

	echo "Creating Directory Structure"
	mkdir OpenSSL OpenSSL/ca OpenSSL/ca/certs OpenSSL/ca/crl OpenSSL/ca/newcerts OpenSSL/ca/private OpenSSL/ca/intermediate OpenSSL/ca/intermediate/certs OpenSSL/ca/intermediate/crl OpenSSL/ca/intermediate/csr OpenSSL/ca/intermediate/newcerts OpenSSL/ca/intermediate/private OpenSSL/ca/intermediate/pkcs12 OpenSSL/ca/intermediate/jks

	chmod 700 $ROOTDIR/private 
	chmod 700 $INTDIR/private
	touch $ROOTDIR/index.txt
	echo 1000 > $ROOTDIR/serial
	echo 1000 > $ROOTDIR/crlnumber

	touch $INTDIR/index.txt
	echo 1000 > $INTDIR/serial
	echo 1000 > $INTDIR/crlnumber

	cp ca.cnf $ROOTDIR/openssl.cnf
	perl -i -pe 's/RootCertAuth/'$ROOTCA'/g' $ROOTDIR/openssl.cnf

	cp intermediate.cnf $INTDIR/openssl.cnf
	perl -i -pe 's/IntermediateCertAuth/'$INTCA'/g' $INTDIR/openssl.cnf
}

function createRootCA(){

	#Create RootCA
	echo "Creating the RootCA Private Key"
	openssl  genrsa -aes256 -out $ROOTDIR/private/$ROOTCA.key.pem -passout pass:$ROOTCAPW 4096

	echo "Giving read permision to RootCA Private Key"
	chmod 400 $ROOTDIR/private/$ROOTCA.key.pem


	echo "Creating RootCA Certificate via RootCA Private Key"
	openssl req -config $ROOTDIR/openssl.cnf -passin pass:$ROOTCAPW -key $ROOTDIR/private/$ROOTCA.key.pem -new -x509 -days $DAYS -sha256 -extensions v3_ca -out $ROOTDIR/certs/$ROOTCA.crt -subj "$SUBJECT/CN=$ROOTCA/"

	echo "Verifing Root CA"
	openssl x509 -noout -text -in $ROOTDIR/certs/$ROOTCA.crt
	echo "Root CA has been created succesfully!"

	echo "Creating the certfication chain"
	cat $ROOTDIR/certs/$ROOTCA.crt > $ROOTDIR/certs/$CACHAIN.crt

	echo "Giving read permision to CA Chain Cert"
	chmod 444 $ROOTDIR/certs/$CACHAIN.crt
}

function verifyCert(){
	CERT=$1

	echo "Verfiying $CERT Certificate"
	openssl verify -crl_check -CAfile $INTDIR/certs/$CACHAIN.crt $INTDIR/certs/$CERT.crt
}

function verifyAuth(){
	AUTH=$1

	echo "Verfiying $AUTH Certificate"
	openssl verify -crl_check -CAfile $ROOTDIR/certs/$CACHAIN.crt $INTDIR/certs/$AUTH.crt
}

function createIntermediateCA(){
	#  Generate Intermediate CA certificate
	echo "Generating Intermadiate CA Private Key"
	openssl genrsa -aes256 -passout pass:$INTCAPW -out $INTDIR/private/$INTCA.key.pem 4096

	echo "Giving read permision to Intermediate CAPrivate Key"
	chmod 400 $INTDIR/private/$INTCA.key.pem

	echo "Create Certificate Sign Request (CSR)"
	openssl req -config $INTDIR/openssl.cnf -passin pass:$INTCAPW -sha256 -new -key $INTDIR/private/$INTCA.key.pem -out $INTDIR/csr/$INTCA.csr -subj "$SUBJECT/CN=$INTCA"

	echo "Sign Intermediate CSR with RootCA"
	openssl ca -config $ROOTDIR/openssl.cnf -extensions v3_intermediate_ca -passin pass:$ROOTCAPW -batch -days $DAYS -notext -md sha256 -in $INTDIR/csr/$INTCA.csr -out $INTDIR/certs/$INTCA.crt

	echo "Giving read permision to Intermediate Cert"
	chmod 444 $INTDIR/certs/$INTCA.crt

	echo "Verfiying intermediate Certificate"
	openssl verify -CAfile $ROOTDIR/certs/$ROOTCA.crt $INTDIR/certs/$INTCA.crt

	echo "Creating the certfication chain"
	cat $INTDIR/certs/$INTCA.crt $ROOTDIR/certs/$ROOTCA.crt > $INTDIR/certs/$CACHAIN.crt

	echo "Giving read permision to CA Chain Cert"
	chmod 444 $INTDIR/certs/$CACHAIN.crt

	echo "Intermediate CA has been created succesfully!"

	echo "Create Trust CA chain"
	$JAVAHOME/keytool -import -noprompt -trustcacerts -alias "trust-ca" -file $INTDIR/certs/$INTCA.crt -keystore $INTDIR/jks/trust.jks -storepass $INTCAPW

}

function createCert(){
	EXTENSION=$1
	CERTNAME=$2
	CERTSUBJ=$3

	#Generating Servers Certificates
	echo "Generating  $CERTNAME Private Key"
	openssl genrsa -aes256 -passout pass:$PASSWORD -out $INTDIR/private/$CERTNAME.key.pem 4096

 	echo "Giving read permision to $CERTNAME Private Key"
	chmod 400 $INTDIR/private/$CERTNAME.key.pem
	
	echo "Create the CSR for $CERTNAME"
	case "$CERTSUBJ" in
		'TRUE')
			openssl req -config $INTDIR/openssl.cnf -passin pass:$PASSWORD -key $INTDIR/private/$CERTNAME.key.pem -new -sha256 -out $INTDIR/csr/$CERTNAME.csr -subj "$SUBJECT/CN=$CERTNAME"
			;;
		'FALSE')
			openssl req -config $INTDIR/openssl.cnf -passin pass:$PASSWORD -key $INTDIR/private/$CERTNAME.key.pem -new -sha256 -out $INTDIR/csr/$CERTNAME.csr
			;;
	esac

	echo "Sign $CERTNAME CSR with $INTCA cert"
	openssl ca -config $INTDIR/openssl.cnf -extensions $EXTENSION -passin pass:$INTCAPW -batch -days $DAYS -notext -md sha256 -in $INTDIR/csr/$CERTNAME.csr -out $INTDIR/certs/$CERTNAME.crt

	echo "Giving read permission to $CERTNAME certificate"
	chmod 444 $INTDIR/certs/$CERTNAME.crt

	echo "Verifying the $CERTNAME certificate"
	openssl x509 -noout -text -in $INTDIR/certs/$CERTNAME.crt

	echo "Using $CACHAIN to verify the certificate"
	openssl verify -CAfile $INTDIR/certs/$CACHAIN.crt $INTDIR/certs/$CERTNAME.crt

	echo "Create PKCS12 Keystore for $CERTNAME"
	openssl pkcs12 -export -in $INTDIR/certs/$CERTNAME.crt -inkey $INTDIR/private/$CERTNAME.key.pem -passin pass:$PASSWORD -out $INTDIR/pkcs12/$CERTNAME.p12 -name $CERTNAME -password pass:$PASSWORD	
	
	$JAVAHOME/keytool -importkeystore -deststorepass $PASSWORD -destkeypass $PASSWORD  -destkeystore $INTDIR/jks/$CERTNAME.jks -srckeystore $INTDIR/pkcs12/$CERTNAME.p12 -srcstoretype PKCS12 -srcstorepass $PASSWORD -alias $CERTNAME	
	
 	# Import the trust CA chain
	$JAVAHOME/keytool -import -noprompt -trustcacerts -alias $CERTNAME -file $INTDIR/certs/$CERTNAME.crt -keystore $INTDIR/jks/trust.jks -storepass $INTCAPW


}

function createINTCA_CH(){
	echo "Remove $CACHAIN"
	sudo rm $INTDIR/certs/$CACHAIN.crt

	echo "Creating the new certfication chain"
	cat $ROOTDIR/certs/$ROOTCA.crt $INTDIR/certs/$INTCA.crt $INTDIR/crl/$INTCA.crl > $INTDIR/certs/$CACHAIN.crt

	echo "Giving read permision to CA Chain Cert"
	chmod 444 $INTDIR/certs/$CACHAIN.crt

}

function createROOTCA_CH(){
	echo "Remove $CACHAIN"
	sudo rm $ROOTDIR/certs/$CACHAIN.crt

	echo "Creating the new certfication chain"
	cat $ROOTDIR/certs/$ROOTCA.crt $ROOTDIR/crl/$ROOTCA.crl > $ROOTDIR/certs/$CACHAIN.crt

	echo "Giving read permision to CA Chain Cert"
	chmod 444 $ROOTDIR/certs/$CACHAIN.crt

}

function createCRL(){
	#Generating Certificate Revokation List
	echo "Generating Certficate Revokation List for $INTCA "
	openssl ca -config $INTDIR/openssl.cnf -gencrl -out $INTDIR/crl/$INTCA.crl -passin pass:$INTCAPW

	echo "Checking the content of CRL "
	openssl crl -in $INTDIR/crl/$INTCA.crl -noout -text

	createINTCA_CH 
}

function createARL(){
	#Generating Authority Revokation List
	echo "Generating Authority Revokation List for $ROOTCA "
	openssl ca -config $ROOTDIR/openssl.cnf -gencrl -out $ROOTDIR/crl/$ROOTCA.crl -passin pass:$ROOTCAPW

	echo "Checking the content of ARL "
	openssl crl -in $ROOTDIR/crl/$ROOTCA.crl -noout -text

	createROOTCA_CH
}

function revokeCert(){
	CERT=$1

	echo "Revoke $CERT Certificate"
	openssl ca -config $INTDIR/openssl.cnf -revoke $INTDIR/certs/$CERT.crt -passin pass:$INTCAPW
	
	verifyCert $CERT
}

function revokeAuth(){
	AUTH=$1
	
	echo "Revoke intermediate Certificate"
	openssl ca -config $ROOTDIR/openssl.cnf -revoke $INTDIR/certs/$AUTH.crt -passin pass:$ROOTCAPW

	verifyAuth $AUTH
}

case "$TYPE" in
	-h|--help) usage ;;
	'init')
		init_dir
		createRootCA
		createIntermediateCA
		COUNTER=0
	        while [ $COUNTER -lt ${#SERVERS[@]} ]; do
				createCert server_cert ${SERVERS[$COUNTER]} 'TRUE'
				let COUNTER=COUNTER+1
	        done
		COUNTER=0
			while [ $COUNTER -lt ${#USERS[@]} ]; do
                createCert usr_cert ${USERS[$COUNTER]} 'TRUE'
                let COUNTER=COUNTER+1
            done
		createARL
		createCRL	
		;;
	'user')
		createCert usr_cert $CERTNAME 'FALSE'
		;;
	'server')
		createCert server_cert $CERTNAME 'FALSE' 
		;;
	'arl')
		createARL 
		;;
	'crl')
		createCRL 
		;;	
	'revokeCert')
		revokeCert $CERTNAME
		createCRL
		;;
	'revokeAuth')
		revokeAuth $CERTNAME
		createARL
		;;
	'verifyCert')
		verifyCert $CERTNAME
		;;
	'verifyAuth')
		verifyAuth $CERTNAME
		;;			
esac



