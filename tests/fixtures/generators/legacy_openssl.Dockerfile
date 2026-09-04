# Legacy OpenSSL 1.0.2u for static ECDH / static RSA / RC4 lab captures.
# Used only by tests/fixtures/generators/lab_legacy_openssl_captures.py.
FROM python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc make perl wget ca-certificates libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/src
# GCC 14 treats implicit declarations as errors; 1.0.2u needs those warnings
# to stay warnings. The GitHub release tarball matches the OpenSSL 1.0.2u SHA-256.
ENV CFLAGS="-Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types -Wno-error=int-conversion -Wno-error=implicit-int"
RUN wget -q https://github.com/openssl/openssl/releases/download/OpenSSL_1_0_2u/openssl-1.0.2u.tar.gz \
    && echo "ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16  openssl-1.0.2u.tar.gz" \
        | sha256sum -c \
    && tar xzf openssl-1.0.2u.tar.gz \
    && cd openssl-1.0.2u \
    && ./config --prefix=/opt/openssl102 no-shared enable-weak-ssl-ciphers \
    && make -j"$(nproc)" \
    && make install_sw \
    && cd / \
    && rm -rf /tmp/src
ENV PATH=/opt/openssl102/bin:$PATH
WORKDIR /
