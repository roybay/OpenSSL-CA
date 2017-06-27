This script is requires openssl installed:

Windows: http://gnuwin32.sourceforge.net/packages/openssl.htm

Modify pki.properties:

OPENSSL=<openssl installation folder>/bin/openssl.exe 

Need to be used MobaXterm as an terminal


./pki-script.sh [type] [Common Name] [CA Name]
	Type: user, server, revokeCert, verifyCert

	Ex: ./pki-script.sh user rbahian_tst

./pki-script.sh [type] [CA Name]
	Type: ca, crl, revokeAuth, verifyAuth

	Ex: ./pki-script.sh crl authority.molpis.com

./pki-script.sh [type]
	Type: arl, init

	Ex: ./pki-script.sh arl
	If openssl folder is exist, ignore the initial configuration (init)
