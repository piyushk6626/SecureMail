FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --home-dir /nonexistent \
        --shell /usr/sbin/nologin --no-create-home nonroot

USER 65532:65532
