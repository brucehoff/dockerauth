# to run:
# docker run -d -v src/main/resources:src/main/resources -p 8080:8080 brucehoff/dockerauth
# docker run -it -p 8080:8080 --name dockerauth brucehoff/dockerauth

FROM maven:3.2-jdk-7-onbuild
RUN mvn clean install
CMD mvn appengine:devserver
