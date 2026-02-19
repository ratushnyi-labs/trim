FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.9.0 AS xx

FROM --platform=$BUILDPLATFORM rust:1.93-alpine3.23 AS builder
COPY --from=xx / /

COPY Cargo.tom[l] zscaler.cr[t] /tmp/
RUN if [ -f /tmp/zscaler.crt ]; then \
        cat /tmp/zscaler.crt >> /etc/ssl/certs/ca-certificates.crt; \
    fi \
    && apk add --no-cache clang lld file

ARG TARGETPLATFORM
RUN xx-apk add --no-cache musl-dev

ARG XSTRIP_VERSION

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY LICENSE ./
COPY src src

RUN TRIPLE="$(xx-info march)-unknown-linux-musl" \
    && if [ -n "$XSTRIP_VERSION" ]; then export XSTRIP_VERSION; fi \
    && xx-cargo build --release \
    && xx-verify "target/${TRIPLE}/release/xstrip" \
    && cp "target/${TRIPLE}/release/xstrip" /xstrip

FROM scratch AS export
COPY --from=builder /xstrip /xstrip

FROM scratch

COPY --from=builder /xstrip /usr/local/bin/xstrip

WORKDIR /work
USER 10000:10000

HEALTHCHECK --interval=30s --timeout=5s --retries=1 \
    CMD ["/usr/local/bin/xstrip", "--help"]

ENTRYPOINT ["/usr/local/bin/xstrip"]
