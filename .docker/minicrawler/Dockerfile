FROM debian:bookworm-slim as minicrawler

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get -y install \
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

# copy minicrawler source
WORKDIR /minicrawler
COPY . /minicrawler

RUN ./autogen.sh \
	&& ./configure --prefix=/var/lib/minicrawler/usr --with-ca-bundle=/var/lib/certs/ca-bundle.crt --with-ca-path=/etc/ssl/certs \
	&& make || exit 42 \
	&& make install || exit 43
