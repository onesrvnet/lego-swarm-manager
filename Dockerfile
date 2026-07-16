FROM alpine:3.20

LABEL org.opencontainers.image.title="lego-swarm-manager"
LABEL org.opencontainers.image.description="Lego container that reads Traefik host labels from Docker Swarm and dynamically issues/renews Let's Encrypt certificates."
LABEL org.opencontainers.image.authors="onesrv, Regh & Meier Services GbR <info@onesrv.net>"
LABEL org.opencontainers.image.source="https://github.com/onesrvnet/lego-swarm-manager"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache bash curl jq docker-cli coreutils grep sed bind-tools openssl

# lego (pin the version you've tested)
ARG LEGO_VERSION=v4.17.4
RUN curl -fsSL "https://github.com/go-acme/lego/releases/download/${LEGO_VERSION}/lego_${LEGO_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin lego

COPY certd.sh /usr/local/bin/certd.sh
RUN chmod +x /usr/local/bin/certd.sh

ENTRYPOINT ["/usr/local/bin/certd.sh"]