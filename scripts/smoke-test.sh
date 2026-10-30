#!/bin/sh
# Starts the image and expects its MCP endpoint to refuse a request without a token.
set -eu
image=$1
name=smoke-$$
docker run -d --name "$name" -e MCP_TOKEN=smoke-test-only -e DOMAINS=example.com -e LAN_HOST=192.0.2.1 -e LAN_RANGES=192.0.2.0/24 -e ADGUARD_URL=http://192.0.2.1 -e AUTHENTIK_URL=http://192.0.2.1 -e AUTHENTIK_PUBLIC_URL=https://auth.example.com -e BASIC_AUTH_USERS=admin "$image" >/dev/null
trap 'docker logs "$name" 2>&1 | tail -20; docker rm -f "$name" >/dev/null' EXIT
sleep 3
ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
status=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -X POST "http://$ip:8080/mcp")
[ "$status" = 401 ] || { echo "Expected 401, got $status"; exit 1; }
