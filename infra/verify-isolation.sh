#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Verifying all 5 PQ-CA networks and internal flags ==="
for net in frontend-net backend-net db-net hsm-net ai-net; do
  internal_flag=$(docker network inspect "$net" --format '{{.Internal}}')
  subnet=$(docker network inspect "$net" --format '{{(index .IPAM.Config 0).Subnet}}')
  echo "Network: $net | Internal: $internal_flag | Subnet: $subnet"
done

echo ""
echo "=== 2. Verifying pqca-nginx attachments (must ONLY be frontend-net & backend-net) ==="
docker inspect pqca-nginx --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} ({{$v.IPAddress}}) {{end}}'
echo ""

echo "=== 3. Verifying Nginx health and static file delivery ==="
curl -fs http://localhost/nginx-health
curl -fsI http://localhost/ | head -n 5