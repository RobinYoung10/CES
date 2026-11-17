#!/usr/bin/env bash
# Generates a self-signed TLS cert for the demo.
# Accepted risk: self-signed is fine for the lab; use a CA-signed cert in production.
set -e
mkdir -p certs
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout certs/nginx.key \
  -out certs/nginx.crt \
  -days 365 -subj "/CN=myserver.com"
echo "Cert written to certs/nginx.crt and certs/nginx.key"
