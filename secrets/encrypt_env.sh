#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=".env"
ENC_FILE=".env.enc"

if [ ! -f "$ENV_FILE" ]; then
  echo "Error: no existe $ENV_FILE"
  echo "Crea primero tu .env con: cp .env.example .env"
  exit 1
fi

openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -in "$ENV_FILE" -out "$ENC_FILE"

echo "Archivo cifrado generado: $ENC_FILE"
echo "Recuerda: .env no debe subirse a Git. Solo .env.enc puede versionarse."
