# dockerauth
This is a proof-of-concept implementation of the Docker delegated authorization mechanism, written in Java.  
The code is NOT production ready.  It's most valuable as an example to start from.   Use at your own risk.  



# To run:
docker run -it --rm -p 8080:8080 --name dockerauth brucehoff/dockerauth
There are two services, one for authorization requests and one for event notifications. 
To exercise the authorization request:
curl "http://192.168.99.100:8080/dockerauth/dockerAuth?service=foo&scope=foo:bar:baz"
(replace 192.168.99.100 with the address of the host to which you've deployed.  If using Docker Machine 
you can find this by running 'docker-machine ls'.)
To exercise the notification service:
curl -X POST -d "{\"event\":\"data\"}" http://192.168.99.100:8080/dockerauth/dockerNotify


The spec' it implements is:
https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md


There were a number of 'gotchas' getting this to work.  To summarize:
- rootcertbundle must actually be a certificate, not a public key.  It IS correct to use a .pem formatted file
- localhost:5000 -> :5000
- The "key ID" (kid) in the JWT "JOSE Header" is not clearly defined.  After much head scratching and searching I found that the definition is: "SPKI DER SHA-256 hash, strip of the last two bytes, base32 encode it and then add a : every four chars."
- The signature must be in P1363 format, NOT ASN.1, which is what the Bouncycastle code generates when signing
- must use url-safe base64 encode of the JWT.  (This IS in the doc's, but I found it to be easily missed.)

