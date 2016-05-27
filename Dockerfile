# to run:
# docker run -d -v src/main/resources:/usr/local/tomcat/src/main/resources -p 8080:8080 brucehoff/dockerauth
# docker run -it --rm -p 8080:8080 --name dockerauth brucehoff/dockerauth

#FROM tomcat:7-jre7
FROM guligo/jdk-maven-ant-tomcat
#RUN apt-get update && apt-get install maven -y
# RUN mvn clean install
#COPY . /usr/local/tomcat/
COPY . /
# This could be a mv, ln, etc. to be more efficient
RUN mvn package
RUN cp /target/dockerauth.war /etc/tomcat-8.0.24/webapps
# apparently you can also mvn tomcat7:deploy, according to http://trimc-devops.blogspot.com/2015/03/running-docker-applications-apache.html
# copy the .war file into the webapp directory of your Tomcat
# Note:  We omit a 'CMD' line, assuming that the base image does this
