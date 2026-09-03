FROM zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3

COPY zeek /opt/securemail/zeek
RUN chmod -R a+rX /opt/securemail

ARG ZEEK_BUNDLE_SHA256=unknown
ARG ZEEK_BASE_DIGEST=sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3
LABEL securemail.zeek_bundle_sha256="${ZEEK_BUNDLE_SHA256}"
LABEL securemail.zeek_base_digest="${ZEEK_BASE_DIGEST}"
