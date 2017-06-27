This script is requires openssl installed:

Windows: http://gnuwin32.sourceforge.net/packages/openssl.htm

Modify pki.properties:

	OPENSSL=\<openssl installation folder\>/bin/openssl.exe 
	Need to be used MobaXterm as an terminal


./pki-script.sh [type] [Common Name] [CA Name]

	Type: 	user		Create User Certificate 
		server		Create Server Certificate
		revokeCert	Revoke client User or Server Certificate
		verifyCert	Verify Client User or Server Certificate 
	
	Ex: ./pki-script.sh user rbahian_tst

./pki-script.sh [type] [CA Name]

	Type: 	ca		Create Intermediate Certificate Authority
		crl		Create Intermediate Certificate Revokation List 
		revokeAuth	Revoke Intermediare Certificate Authority
		verifyAuth 	Verify Intermediate Certificate Atuhority
		
	Ex: ./pki-script.sh crl authority.molpis.com

./pki-script.sh [type]

	Type: 	arl		Create Root CA Revokation List which is called as an Authority Revoakation List
		init		Create Initial Certificated Batch operation it can be managed by pki.properties
		
	Ex: ./pki-script.sh arl
	If openssl folder is exist, ignore the initial configuration (init)
