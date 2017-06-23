./pki-script [type] [Common Name]

	Type: user, server, revokeCert, revokeAuth
	Ex: ./pki-scripts user rbahian_tst
	
./pki-script [type]

	Type: arl, crl, init
        Ex: ./pki-scripts arl
        If OpenSSL folder is exist, ignore the initial configuration (init)
