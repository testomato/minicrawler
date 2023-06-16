FROM debian:latest

ENV LANGUAGE en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LC_ALL C
ENV DEBIAN_FRONTEND noninteractive

ENV CFLAGS "-O3 -g -fstack-protector-strong"

RUN apt-get -qqy update && apt-get -qqy install \
# minicrawler dev deps
	libc-ares-dev \
	zlib1g-dev \
	libicu-dev \
	libssl-dev \
	libnghttp2-dev \
\
# build tool
	make \
	autoconf \
	automake \
	autotools-dev \
	build-essential \
	libtool \
	gcc \
\
# php for testing
	php \
\
# tools
	curl \
	ca-certificates \
	apt-transport-https \
	locales \
	tzdata \
\
	&& sed -i 's/^.*\(en_US.UTF-8\)/\1/' /etc/locale.gen \
	&& locale-gen \
	&& ln -sf "/usr/share/zoneinfo/Europe/Prague" /etc/localtime && dpkg-reconfigure tzdata \
	&& rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
# update certificates \
	&& mkdir -p /var/lib/certs \
	&& curl -s -f -L https://curl.se/ca/cacert.pem -o ca-bundle.crt \
  	&& cat /etc/ssl/certs/ca-certificates.crt >> ca-bundle.crt \
   && cp -v ca-bundle.crt /var/lib/certs/ca-bundle.crt


ENV LC_ALL en_US.UTF-8

ARG PREFIX="/var/lib/minicrawler/usr"

WORKDIR /minicrawler