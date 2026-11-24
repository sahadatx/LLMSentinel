#!/bin/sh
set -eu

api_url="${SENTINEL_API_URL:-http://localhost:8000}"
case "$api_url" in
  https://*|http://localhost:*|http://127.0.0.1:*) ;;
  *) echo "SENTINEL_API_URL must be HTTPS, except for loopback development" >&2; exit 1 ;;
esac
case "$api_url" in
  *[!A-Za-z0-9._:/-]*) echo "SENTINEL_API_URL contains unsupported characters" >&2; exit 1 ;;
esac
while [ "${api_url%/}" != "$api_url" ]; do
  api_url=${api_url%/}
done

umask 077
printf "window.__SENTINEL_API__ = '%s';\n" "$api_url" > /tmp/runtime-config.js
