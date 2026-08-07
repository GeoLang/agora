FROM rust:bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p agora-server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false agora

COPY --from=builder /app/target/release/agora-server /usr/local/bin/agora-server

USER agora

ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["agora-server"]
