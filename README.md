# dockerauth
This is a proof-of-concept implementation of the Docker delegated authorization mechanism, written in Java.  The code is NOT production ready.  It's most valuable as an example to start from.   Use at your own risk.  etc/.keystore contains a self-signed cert used to enable SSL in the authorization service.  THIS IS ONLY FOR TESTING.


## To Run
### Enable the use of an 'insecure registry'
This allows us to run the demo without setting up a proper certificate chain for the registry service.  The instructions for doing so are here:
https://docs.docker.com/registry/insecure/#deploying-a-plain-http-registry
If using Docker Machine, use 'docker-machine ls' to get the IP address of the daemon, e.g.
```
docker-machine ls

NAME      ACTIVE   DRIVER       STATE     URL                         SWARM   DOCKER    ERRORS
...
default   *        virtualbox   Running   tcp://0.0.0.0:2376           v1.11.2 
...
```
The IP address shown, if different from the example, will replace '0.0.0.0' in several places below.  Now remove the existing machine,
```
docker-machine rm default
```
and recreate, allowing the insecure registry:
```
docker-machine create --driver virtualbox --engine-insecure-registry 0.0.0.0:5000 default
```
(The 'gotcha' here is that docker-machine may create 'default' using a new IP address.  If you run into this problem one solution is to use a back-end machine/daemon for executing docker commands which is different from the one used to run the registry and authorization service containers.  You would first start the back end running the containers and then enter its IP address in the '--engine-insecure-registry' parameter when starting the second daemon.)

### Generate the key used to sign authorization tokens, along with the corresponding certificate
The certificate for the key is shared between the authorization service and the registry.
```
mkdir -p signingkey
openssl ecparam -name secp256r1 -genkey | openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt > signingkey/privatekey.pem
openssl req -new -x509 -key signingkey/privatekey.pem -out signingkey/cert.pem -days 36500
```
(In the choice of elliptic curve for key generation, the Docker registry seems to require one of secp224r1, secp256r1, secp384r1, secp521r1.  This code works with the 256 bit algorithm.)
### Run the authorization service
#### interactively:
```
docker run -it --rm --name dockerauth -v ${PWD}/signingkey:/keys -p 8080:8080 -p 8443:8443 brucehoff/dockerauth

```
#### or detached:
```
docker run -d --name dockerauth -v ${PWD}/signingkey:/keys -p 8080:8080 -p 8443:8443 brucehoff/dockerauth
```
Running interactively lets you see the server logs as they are generated, which is helpful for seeing how notification events work.

There are two services, one for authorization requests and one for event notifications.   The registry seems to insist that the authorization service run over SSL (HTTPS).  The notification callback can run over HTTP or HTTPS but the registry throws exceptions if its SSL certificate is self-signed, so we simply use HTTP for this service.

To exercise the authorization request:
```
curl -H Authorization:"Basic dW5hbWU6cHdk" -k "https://0.0.0.0:8443/dockerauth-1.0/dockerAuth?service=my.registry.com&scope=repository:username/reponame:push,pull"
```
To exercise the notification service:
```
curl -X POST -d "{\"event\":\"data\"}" http://0.0.0.0:8080/dockerauth-1.0/dockerNotify
```
Whatever text you put after "-d" will appear in the server logs.

### Run the registry using the generated keys
(You may have to change the authorization service IP address in config.yml, which you can retrieve from  https://github.com/brucehoff/dockerauth .)
```
docker run -it --rm -p 5000:5000 --name registry \
-v ${PWD}/signingkey/cert.pem:/etc/docker/registry/cert.pem \
-v ${PWD}/etc/config.yml:/etc/docker/registry/config.yml registry:2 
```

You may now make Docker commands to the registry, e.g.
```
docker login 0.0.0.0:5000
docker push 0.0.0.0:5000/username/reponame
```
(You can give any user name and password when prompted to log in.)

## Lessons learned
The specification implemented by the authorization service is:
https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md

There were a number of 'gotchas' getting the service to work.  To summarize:
- rootcertbundle must actually be a certificate, not a public key.  It IS correct to use a .pem formatted file
- localhost:5000 -> :5000 in config.yml
- The "key ID" (kid) in the JWT "JOSE Header" is not clearly defined.  After much head scratching and searching I found that the definition is: "SPKI DER SHA-256 hash, strip off the last two bytes, base32 encode it and then add a : every four chars."
- must use latest versions of JWT (>=0.7.0) and Bouncycastle (>=1.55) to get signature in P1363 format rather than ASN.1
- must use url-safe base64 encode of the JWT.  (This IS in the doc's, but I found it to be easily missed.)

