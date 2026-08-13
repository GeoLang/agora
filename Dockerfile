FROM rust:bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p agora-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# the RDS roots are not in any public trust store, so sslmode=verify-full needs
# this bundle named as sslrootcert. it is public, and only roots, no key.
RUN curl -fsSL https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
    -o /etc/ssl/rds-global-bundle.pem

RUN useradd -r -s /bin/false agora

COPY --from=builder /app/target/release/agora-server /usr/local/bin/agora-server

USER agora

ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["agora-server"]
