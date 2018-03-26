FROM centos:7 as builder

WORKDIR /usr/src
RUN yum install -y epel-release  && \
    yum install -y git \
                   pcre \
                   pcre-static \
                   pcre-devel \
                   gcc \
                   make \
                   openssl-devel \
                   zlib-devel \
                   readline-devel \
                   openssl \
                   curl \
                   gcc-c++ \
                   flex \
                   bison \
                   yajl \
                   yajl-devel \
                   curl-devel \
                   GeoIP-devel \
                   doxygen \
                   automake \
                   libtool \
                   ssdeep-devel \
                   lmdb-devel \
                   libxml2-devel \
                   httpd-devel \
                   libevent-devel

RUN yum -y install centos-release-scl && \
    yum -y install devtoolset-7-gcc* && \
    scl enable devtoolset-7 bash

RUN LUA_URL=http://www.lua.org/ftp/lua-5.3.3.tar.gz; \
    LUA_MD5=703f75caa4fdf4a911c1a72e67a27498; \
    echo "Installing lua"; \
    curl -SL ${LUA_URL} -o lua-5.3.3.tar.gz \
            && echo "${LUA_MD5} lua-5.3.3.tar.gz" | md5sum -c \
            && mkdir -p /usr/src/lua \
            && tar -xzf lua-5.3.3.tar.gz -C /usr/src/lua --strip-components=1 \
            && rm lua-5.3.3.tar.gz \
            && make -C /usr/src/lua linux test install MYCFLAGS=-fPIC
COPY src /usr/
ADD http://www.haproxy.org/download/1.8/src/haproxy-1.8.4.tar.gz /root/
RUN tar zxf haproxy-1.8.4.tar.gz && \
    cd haproxy-1.8.4/contrib/modsecurity
RUN cd haproxy-1.8.4/contrib/modsecurity && \
    git clone --depth 1 -b v2/master https://github.com/SpiderLabs/ModSecurity.git && \
    cd ModSecurity && ./autogen.sh && \
    sed -i 's/^LUA_POSSIBLE_LIB_NAMES.*/LUA_POSSIBLE_LIB_NAMES="lua lua53 lua5.3 lua52 lua5.2 lua-5.3"/g' configure && \
    #sed -i 's/APR_LOCK_DEFAULT/APR_LOCK_PROC_PTHREAD/g;' apache2/modsecurity.c && \
    ./configure --help && \
    ./configure --prefix=/usr \
                --disable-apache2-module \
                --enable-standalone-module \
                --enable-alp2 \
                --enable-pcre-study \
                --enable-lua-cache \
                --enable-debug-mem \
                --enable-pcre-jit && \
    make clean standalone install
COPY src/ /root/haproxy-1.8.4/contrib/modsecurity/
RUN cd haproxy-1.8.4/contrib/modsecurity && \
    mkdir -p $PWD/include && \
    cp ModSecurity/standalone/*.h $PWD/include && \
    cp ModSecurity/apache2/*.h $PWD/include && \
    sed -i 's/^APACHE2_INC.*/APACHE2_INC := \/usr\/include\/httpd/g' Makefile && \
    sed -i 's/^MODSEC_INC.*/MODSEC_INC := include/g' Makefile && \
    sed -i 's/^APR_INC.*/APR_INC := \/usr\/include\/apr-1/g' Makefile && \
    sed -i 's/^MODSEC_LIB.*/MODSEC_LIB := \/usr\/lib/g' Makefile && \
    sed -i 's/LIBS +=.*/LIBS += -lpthread -lm -ldl $(EVENT_LIB) -levent_pthreads -lcurl -lapr-1 -laprutil-1 -lxml2 -lpcre -lyajl -lfuzzy -llua/g' Makefile && \
    make clean install

# mod_defender
RUN git clone --depth 1 https://github.com/VultureProject/mod_defender.git && \
    cd haproxy-1.8.4/contrib/mod_defender && \
    sed -i 's/^APACHE2_INC.*/APACHE2_INC := \/usr\/include\/httpd/g' Makefile && \
    sed -i 's/^APR_INC.*/APR_INC := \/usr\/include\/apr-1/g' Makefile && \
    . /opt/rh/devtoolset-7/enable && \
    make clean install MOD_DEFENDER_SRC=/root/mod_defender

FROM centos:7
RUN yum install -y epel-release
RUN yum -y install \
                    git \
                    libevent \
                    apr \
                    apr-util \
                    yajl \
                    ssdeep \
                    libxml2 \
                    curl \
                    openssl \
                    pcre-static \
                    libcurl

RUN mkdir -p /etc/modsecurity /var/log/modsecurity /var/cache/modsecurity/tmp && \
    cd /etc/modsecurity && \
    git clone --depth 1 https://github.com/SpiderLabs/owasp-modsecurity-crs.git && \
    mv owasp-modsecurity-crs/crs-setup.conf.example /etc/modsecurity/crs-setup.conf && \
    mv owasp-modsecurity-crs/rules/ /etc/modsecurity/ && \
    rm -fr owasp-modsecurity-crs

RUN mkdir -p /etc/defender /var/lib/defender && \
     curl -sSS -o /etc/defender/core.rules \
     https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules

COPY --from=builder /usr/local/bin/modsecurity /usr/bin/modsecurity
COPY --from=builder /root/haproxy-1.8.4/contrib/modsecurity/ModSecurity/unicode.mapping /etc/modsecurity/unicode.mapping
COPY --from=builder /root/haproxy-1.8.4/contrib/mod_defender/defender /usr/bin/defender
COPY modsecurity.conf spoe-modsecurity.conf main.conf /etc/modsecurity/
COPY defender.conf spoe-defender.conf /etc/defender/
ENTRYPOINT ["/usr/bin/modsecurity"]
CMD ["-f",  "/etc/modsecurity/main.conf", "-d", "-c", "pipelining", "-c", "fragmentation", "-c", "async"]

#ENTRYPOINT ["/usr/bin/defender"]
#CMD ["-n", "4", "-f",  "/etc/defender/defender.conf", "-d", "-c", "pipelining", "-c", "fragmentation", "-c", "async", "-l", "var/log/defender"]
