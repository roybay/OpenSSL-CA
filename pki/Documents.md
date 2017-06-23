OpenSSL Self Signed Certificate CA
 
Check the automation script… PJM project. 
 
 
Create the Root CA
------------------
Create A directory structure to keep track of signed certificate 

Make CA folder \
mkdir ca \
mkdir certs crl newcerts private \
chmod 700 private \
touch index.txt \
echo 1000 > serial 
 
Prepare configuration file: 

vi openssl.cnf \
(Find the detail form reference link above)
 
Create the Root Key

openssl genrsa -aes256 -out private/ca.key.pem 4096 \
Enter Password \
Confirm Password \
Give a read permission \
chmod 400 private/ca.key \
 
Create the Root Certificate

openssl req -config openssl.cnf \
-key private/ca.key \
-new -x509 \
-days 7300 \
-sha256 \
-extensions v3_ca \
-out certs/ca.cert \
Enter ca.kay.pem password / Password1 \
Enter required fields value
 
Verify Root Certificate:

openssl x509 -noout -text -in certs/ca.crt 
 
Create the Intermediate CA
--------------------------
Create Intermediate Certificate (purpose of keeping Root Cert isolated)

mkdir ca/intermediate \
cd ca/intermediate \
mkdir certs crl csr newcerts private \
chmod 700 private \
touch index.txt \
echo 1000 > serial \
echo 1000 > crlnumber (purpose of keep track of revocation list)
 
Create intermediate configuration file: (only few things are different)
 
Create the intermediate Key

Go to  ca folder \
openssl genrsa -aes256 -out intermediate/private/intermediate.key 4096 \
Enter intermediate.key password / Password2 \
Verify Password \
Give a read permission \
chmod 400 intermediate/private/intermediate.key
 
Create intermediate Certificate Signing Request (CSR)

openssl req -config intermediate/openssl.cnf \
-new \
-sha256 \
-key intermediate/private/intermediate.key \
-out intermediate/csr/intermediate.csr
Enter intermediate.key password
Enter required fields value
Common name must be different
 
Sign the Intermediate CSR via the RootCA:
openssl ca \
-config openssl.cnf \
-extensions v3_intermediate_ca \
-days 3650 \
-notext \
-md sha256 \
-in intermediate/csr/intermediate.csr \
-out intermediate/certs/intermediate.crt
Enter RootCa Password
Enter Y for signing the certificate
Give a read permission:
chmod 444 intermediate/certs/intermediate.crt
 
Not: ca/index.txt now has the intermadiate certification reference do not add or delete this file
 
 
Verify Intermediate Cert:
openssl verify -CAfile certs/ca.crt intermediate/certs/intermediate.crt
 
Create the Certification Chain File: 
cat intermediate/certs/intermediate.crt \
certs/ca.crt > intermediate/certs/ca-chain.crt
Give a read permission:
chmod 444 intermediate/certs/ca-chain.crt
 
Sign Serve and Client Certificates
    Create a key
openssl genrsa -aes256 -out intermediate/private/www.roylab.com.key 2048
Enter password / Password3
Verify the password
    Give read permission
chmod 400 intermediate/private/www.roylab.com.key
 
openssl genrsa -aes256 -out intermediate/private/rbahian.key 2048
Enter password / Password3
Verify the password
    Give read permission
chmod 400 intermediate/private/rbahian.key
 
Create a CSR
openssl req \
-config intermediate/openssl.cnf \
-key intermediate/private/www.roylab.com.key \
-new \
-sha256 \
-out intermediate/csr/www.roylab.com.csr
Enter www.example.com.key.pem password
Enter required fields value
Common name www.roylab.com
 
openssl req \
-config intermediate/openssl.cnf \
-key intermediate/private/rbahian.key \
-new \
-sha256 \
-out intermediate/csr/rbahian.csr
Enter roy.bahian.key.pem password
Enter required fields value
Common name roy.bahian 
 
Sign the CSR via Intermediate CA 
Not: server_cert or usr_cert extension need to be used
openssl ca \
-config intermediate/openssl.cnf \
-extensions server_cert -days 375 \
-notext \
-md sha256 \
-in intermediate/csr/www.roylab.com.csr \
-out intermediate/certs/www.roylab.com.crt
Enter IntermediateCA password
Enter Y for signing the certificate
Give a read permission:
chmod 444 intermediate/certs/www.roylab.com.crt
 
openssl ca \
-config intermediate/openssl.cnf \
-extensions usr_cert -days 375 \
-notext \
-md sha256 \
-in intermediate/csr/rbahian.csr \
-out intermediate/certs/rbahian.crt
Enter IntermediateCA password
Enter Y for signing the certificate
Give a read permission:
chmod 444 intermediate/certs/rbahian.crt
 
Not: ca/intermediate//index.txt now has the new certification reference do not add or delete this file
 
 
Verify the Certificate
openssl x509 -noout -text -in intermediate/certs/rbahian.crt
Use CA certificate chain to verify the certificate
openssl verify \
-CAfile intermediate/certs/ca-chain.crt \
intermediate/certs/rbahian.crt
 
Deploy the Certificate to the Server 
Need to be supply below files
ca-chain.crt
rbahian.key
rbahian.crt
 
If third-party CSR is signed then no need to supply private key. 
ca-chain.crt
rbahian.crt
 
Certificate Revocation List
    Publish the CRL at a publicly accessible location 
http://example.com/intermediate.crl.pem
 
Not: Some applications vendors have deprecated CRLs and are instead using the Online Certificate Status Protocol (OCSP)
 
Create the CRL
openssl ca -config intermediate/openssl.cnf \
-gencrl \
-out intermediate/crl/intermediate.crl
 
Check the content of CRL
openssl crl -in intermediate/crl/intermediate.crl -noout -text
 
Revoking Certificate 
openssl ca -config intermediate/openssl.cnf -revoke intermediate/certs/www.example.com.crt
Need to create CRL again in order to see the revoked cert in the list
 
Convert
openssl x509 -in cert.pem -out cert.der -outform DER
 
