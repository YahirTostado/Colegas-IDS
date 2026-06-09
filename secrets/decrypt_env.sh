#!/usr/bin/env bash
set -euo pipefail

ENV_FILE=".env"
ENC_FILE=".env.enc"

if [ ! -f "$ENC_FILE" ]; then
  echo "Error: no existe $ENC_FILE"
  echo "Primero genera el archivo cifrado con: ./secrets/encrypt_env.sh"
  exit 1
fi

if [ -f "$ENV_FILE" ]; then
  echo "Advertencia: ya existe $ENV_FILE"
  read -p "¿Deseas sobrescribirlo? (s/N): " confirm
  if [[ "$confirm" != "s" && "$confirm" != "S" ]]; then
    echo "Operación cancelada."
    exit 0
  fi
fi

openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in "$ENC_FILE" -out "$ENV_FILE"

echo "Archivo descifrado generado: $ENV_FILE"
echo "No subas .env a Git."
