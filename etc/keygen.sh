#!/bin/sh
java -classpath /target/dockerauth-1.0/WEB-INF/lib/bcpkix-jdk15on-1.54.jar:/target/dockerauth-1.0/WEB-INF/lib/jackson-core-2.4.2.jar:/target/dockerauth-1.0/WEB-INF/lib/bcprov-ext-jdk15on-1.54.jar:/target/dockerauth-1.0/WEB-INF/lib/jackson-databind-2.4.2.jar:/target/dockerauth-1.0/WEB-INF/lib/bcprov-jdk15on-1.51.jar:/target/dockerauth-1.0/WEB-INF/lib/jjwt-0.6.0.jar:/target/dockerauth-1.0/WEB-INF/lib/commons-codec-1.9.jar:/target/dockerauth-1.0/WEB-INF/lib/json-simple-1.1.jar:/target/dockerauth-1.0/WEB-INF/lib/commons-io-2.4.jar:/target/dockerauth-1.0/WEB-INF/lib/jstl-1.2.jar:/target/dockerauth-1.0/WEB-INF/lib/jackson-annotations-2.4.0.jar:/target/dockerauth-1.0/WEB-INF/classes dockerauth.CertificateHelper /keys