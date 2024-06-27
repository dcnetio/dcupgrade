FROM ubuntu:22.04
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NOWARNINGS="yes"
COPY libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb /tmp/
RUN apt-get update && apt-get upgrade -y && apt-get -y install  build-essential libssl-dev  libcurl4-openssl-dev dkms git wget \
&& echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' |  tee /etc/apt/sources.list.d/intel-sgx.list \
&& wget  -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1  sudo apt-key add  \
&& apt-get update -y &&  apt-get install -y libsgx-dcap-default-qpl &&  apt-get install -y  libsgx-dcap-ql-dev \
&& ln -s /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1 /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so \
&& sudo dpkg -i /tmp/libssl1.1_1.1.1f-1ubuntu2.19_amd64.deb \
&& apt-get -y install  --no-install-recommends libsgx-enclave-common && apt-get -y install libsgx-quote-ex \
&& apt-get remove git wget -y && apt-get clean autoclean && apt-get autoremove --yes \
&& rm -rf /var/lib/{apt,dpkg,cache,log} && rm -rf /tmp/* && rm -rf /var/tmp/*
COPY sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
COPY dcupgrade /usr/local/bin/
COPY auth /opt/dcnetio/data/init/
ENTRYPOINT ["dcupgrade"]
