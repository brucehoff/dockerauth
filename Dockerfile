# to run:
# docker run -d -v src/main/resources:/usr/local/tomcat/src/main/resources -p 8080:8080 brucehoff/dockerauth
# docker run -it --rm -p 8080:8080 --name dockerauth brucehoff/dockerauth

FROM guligo/jdk-maven-ant-tomcat
COPY . /
RUN mvn package
# copy the .war file into the webapp directory of your Tomcat
# This could be a mv, ln, etc. to be more efficient
RUN cp /src/main/resources/* /etc/tomcat-8.0.24/src/main/resources
RUN cp /target/dockerauth.war /etc/tomcat-8.0.24/webapps
# apparently you can also mvn tomcat7:deploy, according to http://trimc-devops.blogspot.com/2015/03/running-docker-applications-apache.html
# Note:  We omit a 'CMD' line, assuming that the base image does this
