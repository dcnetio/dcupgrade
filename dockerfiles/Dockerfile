FROM ubuntu:20.04
ENV DEBIAN_FRONTEND noninteractive
ENV DEBCONF_NOWARNINGS="yes"
RUN apt-get update && apt-get upgrade -y && apt-get -y install  build-essential libssl-dev  dkms git wget \
&& echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' |  tee /etc/apt/sources.list.d/intel-sgx.list \
&& wget  -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key  | APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1  apt-key add  \
&& apt-get update -y &&  apt-get install -y libsgx-dcap-default-qpl &&  apt-get install -y  libsgx-dcap-ql-dev \
&& ln -s /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1 /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so \
&& apt-get -y install  --no-install-recommends libsgx-enclave-common && apt-get -y install libsgx-quote-ex \
&& apt-get remove git wget -y && apt-get clean autoclean && apt-get autoremove --yes \
&& rm -rf /var/lib/{apt,dpkg,cache,log} && rm -rf /tmp/* && rm -rf /var/tmp/* 
COPY sgx_default_qcnl.conf /etc/sgx_default_qcnl.conf
COPY dcupgrade /usr/local/bin/
COPY auth /opt/dcnetio/data/init/
ENTRYPOINT ["dcupgrade"]
