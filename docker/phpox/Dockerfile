FROM alpine:3.18
#
# Install packages
RUN apk -U --no-cache add \
               build-base \
               file \
               git \
               make \
               php \
               php81-dev \
               php-tokenizer \
               python3 \
               py3-pip \
               python3-dev \
               re2c && \
#
# Install bfr sandbox from git
    git clone --depth=1 https://github.com/mushorg/BFR /opt/BFR && \
    cd /opt/BFR && \
    php --version && \
    phpize && \
    ./configure \
      --enable-bfr && \
    make && \
    make install && \
    cd / && \
    rm -rf /opt/BFR /tmp/* /var/tmp/* && \
    php --ini | grep Loaded && \
    echo "zend_extension = "$(find /usr -name bfr.so) >> /etc/php81/php.ini && \
#
# Install PHP Sandbox
    git clone --depth=1 https://github.com/mushorg/phpox /opt/phpox && \
    cd /opt/phpox && \
    pip install -r requirements.txt && \
    make && \
#
# Clean up
    apk del --purge build-base \
                    git \
                    php-dev \
                    python3-dev && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*
#
# Set workdir and start phpsandbox
USER nobody:nobody
WORKDIR /opt/phpox
CMD ["python3", "sandbox.py"]
