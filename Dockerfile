# toro-auth: auth.torosaba.net (共通認証)
#
#   docker build -t toro-auth .
#
# musl で静的にリンクして scratch に載せる。CA 証明書はバイナリに埋め込んである (webpki-roots)

FROM rust:1.99-alpine@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d AS compile
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
# 依存だけを先にビルドして、ソースだけを変えたときのビルドを速くする
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir -p src assets/home && echo 'fn main() {}' > src/main.rs && touch src/lib.rs assets/home/token.ts \
 && cargo build --release --locked \
 && rm -rf src assets
COPY src ./src
COPY assets ./assets
RUN touch src/main.rs src/lib.rs assets/home/token.ts && cargo build --release --locked
RUN mkdir /data-empty

FROM scratch
COPY --from=compile /src/target/release/toro-auth /toro-auth
# 90 日トークンの世代の記録。名前付きボリュームは、この持ち主を受け継ぐ
COPY --from=compile --chown=65532:65532 /data-empty /data
USER 65532:65532
ENV PORT=8080
# 8080: 公開 (トンネルの行き先)。8081: api / mcp のトークンの確認。Docker の内側のネットワークだけに置き、公開しない
EXPOSE 8080 8081
HEALTHCHECK --interval=15s --timeout=4s --start-period=5s --retries=3 CMD ["/toro-auth", "healthcheck"]
ENTRYPOINT ["/toro-auth"]
