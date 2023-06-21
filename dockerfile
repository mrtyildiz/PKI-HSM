FROM python:latest
RUN apt install -y && apt update -y && apt upgrade -y && apt dist-upgrade -y
RUN mkdir -p /app
WORKDIR /app
RUN mkdir -p /opt/procrypt/km3000/config
RUN apt-get install gnutls-bin -y
