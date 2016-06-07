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
default   *        virtualbox   Running   tcp://192.168.99.100:2376           v1.11.2 
...
```
The IP address shown, if different from the example, will replace '192.168.99.100' in several places below.  Now remove the existing machine,
```
docker-machine rm default
```
and recreate, allowing the insecure registry:
```
docker-machine create --driver virtualbox --engine-insecure-registry 192.168.99.100:5000 default
```

### Generate the key used to sign authorization tokens
The certificate for the key is shared between the authorization service and the registry.
```
mkdir -p signingkey
docker run -it -v ${PWD}/signingkey:/keys --rm brucehoff/dockerauth /etc/keygen.sh
```
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
curl -k "https://192.168.99.100:8443/dockerauth-1.0/dockerAuth?service=my.registry.com&scope=repository:username/reponame:push,pull"
```
To exercise the notification service:
```
curl -X POST -d "{\"event\":\"data\"}" http://192.168.99.100:8080/dockerauth-1.0/dockerNotify
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
docker push 192.168.99.100:5000/username/reponame
```


## Lessons learned
The specification implemented by the authorization service is:
https://github.com/docker/distribution/blob/master/docs/spec/auth/token.md

There were a number of 'gotchas' getting the service to work.  To summarize:
- rootcertbundle must actually be a certificate, not a public key.  It IS correct to use a .pem formatted file
- localhost:5000 -> :5000 in config.yml
- The "key ID" (kid) in the JWT "JOSE Header" is not clearly defined.  After much head scratching and searching I found that the definition is: "SPKI DER SHA-256 hash, strip of the last two bytes, base32 encode it and then add a : every four chars."
- The signature must be in P1363 format, NOT ASN.1, which is what the Bouncycastle code generates when signing
- must use url-safe base64 encode of the JWT.  (This IS in the doc's, but I found it to be easily missed.)

