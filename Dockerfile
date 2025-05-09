FROM perl:5.38-slim

# ビルド環境
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential libgmp-dev libssl-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# XS モジュールをビルド
RUN cpanm --quiet --notest CryptX Crypt::PBKDF2

WORKDIR /app
COPY decrypt_aes_gcm.pl .
ENTRYPOINT ["perl", "/app/decrypt_aes_gcm.pl"]
