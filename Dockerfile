FROM openjdk:11.0.12-jdk-slim-buster

RUN apt-get update && apt-get upgrade -y

ADD target/decryption-service-2.1.2.jar decryption.jar
