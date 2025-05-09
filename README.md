# perl_decrypt

## Installation

```bash
$ cp .env.example .env

# Edit for your environment
# PASSPHRASE に、暗号化時のパスワードを設定してください
$ vi .env



docker compose build

docker compose up


成功すると data/ フォルダに
sample.dec.txt
が出力されます


以下のように実行すると、salt・IV・key などの情報を出力します
docker compose run decryptor -i /data/sample.bin -o /data/sample.dec.txt --passenv PASSPHRASE --verbose
