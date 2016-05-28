#
# to generate keys
# docker run -it /path/to/shared/keys:/keys --rm brucehoff/dockerauth /etc/keygen.sh /keys
# to run interactively:
# docker run -it --rm -v /path/to/shared/keys:/keys -p 8443:8443 brucehoff/dockerauth
# to run detached:
# docker run -d --name dockerauth -v /path/to/shared/keys:/keys -p 8443:8443 brucehoff/dockerauth
# The run registry, using the generated keys (you may have to change the auth svc IP address in config.yml):
# docker run -it --rm -p 5000:5000  --name registry -v /path/to/shared/keys/cert.pem:/etc/docker/registry/cert.pem -v ${PWD}/etc/config.yml:/etc/docker/registry/config.yml registry:2 

FROM guligo/jdk-maven-ant-tomcat
COPY . /
RUN mvn package
# move the .war file into the webapp directory of your Tomcat
RUN mv /target/dockerauth.war /etc/tomcat-8.0.24/webapps
# Enable SSL. .keystore contains a self-signed cert.  THIS IS ONLY FOR TESTING.
COPY etc/.keystore /root/
COPY etc/server.xml etc/catalina.properties /etc/tomcat-8.0.24/conf/
