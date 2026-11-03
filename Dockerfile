# toro-auth: auth.torosaba.net / mcp.torosaba.net (共通認証と AI コネクタ)
#
#   docker build -t toro-auth .
#
# musl で静的にリンクして scratch に載せる。CA 証明書はバイナリに埋め込んである (webpki-roots)

FROM rust:1.98-alpine AS compile
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
# 依存だけを先にビルドして、ソースだけを変えたときのビルドを速くする
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src
COPY src ./src
COPY assets ./assets
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM scratch
COPY --from=compile /src/target/release/toro-auth /toro-auth
USER 65532:65532
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 CMD ["/toro-auth", "healthcheck"]
ENTRYPOINT ["/toro-auth"]
