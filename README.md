# dockerauth
This is a proof-of-concept implementation of the Docker delegated authorization mechanism, written in Java.  
The code is NOT production ready.  It's most valuable as an example to start from.   Use at your own risk. 
etc/.keystore contains a self-signed cert used to enable SSL.  THIS IS ONLY FOR TESTING.


## To run:
### Generate the key used to sign authorization tokens.
The key is shared between the authorization service and the registry.
{code}
docker run -it /path/to/shared/keys:/keys --rm brucehoff/dockerauth /etc/keygen.sh /keys
{code}
### Run the authorization service
#### interactively:
{code}
# docker run -it --rm -v /path/to/shared/keys:/keys -p 8443:8443 brucehoff/dockerauth
{code}
#### or detached:
{code}
docker run -d --name dockerauth -v /path/to/shared/keys:/keys -p 8443:8443 brucehoff/dockerauth
{code}

There are two services, one for authorization requests and one for event notifications. 
To exercise the authorization request:
{code}
curl "https://192.168.99.100:8443/dockerauth-1.0/dockerAuth?service=foo&scope=foo:bar:baz"
{code}
(Replace 192.168.99.100 with the address of the host to which you've deployed.  If using Docker Machine 
you can find this by running 'docker-machine ls'.)
To exercise the notification service:
{code}
curl -X POST -d "{\"event\":\"data\"}" https://192.168.99.100:8443/dockerauth/dockerNotify
{code}

### Run the registry using the generated keys (you may have to change the auth svc IP address in config.yml, which you can retrieve from the source Github project):
{code}
# docker run -it --rm -p 5000:5000  --name registry \
-v /path/to/shared/keys/cert.pem:/etc/docker/registry/cert.pem \
-v ${PWD}/etc/config.yml:/etc/docker/registry/config.yml registry:2 
{code}



## Lessons learned:
The specification implemented by the authorization service is:
https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md

There were a number of 'gotchas' getting the service to work.  To summarize:
- rootcertbundle must actually be a certificate, not a public key.  It IS correct to use a .pem formatted file
- localhost:5000 -> :5000
- The "key ID" (kid) in the JWT "JOSE Header" is not clearly defined.  After much head scratching and searching I found that the definition is: "SPKI DER SHA-256 hash, strip of the last two bytes, base32 encode it and then add a : every four chars."
- The signature must be in P1363 format, NOT ASN.1, which is what the Bouncycastle code generates when signing
- must use url-safe base64 encode of the JWT.  (This IS in the doc's, but I found it to be easily missed.)

