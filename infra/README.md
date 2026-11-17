# PQ-CA Network Topology & Reverse Proxy (`SCRUM-210`, `SCRUM-221`)

## 5-Tier Network Segmentation (`NFR-SEC-013`, `NFR-SEC-014`)
- **`frontend-net`**: Public entry bridge (`Nginx` reverse proxy on port `80`/`443`).
- **`backend-net` (`--internal`)**: Internal service mesh (`FastAPI API Gateway`, `CA Core`, `RA`, `OCSP`, `CRL`, `OV Agent`).
- **`db-net` (`--internal`)**: Isolated persistence network for `PostgreSQL`.
- **`hsm-net` (`--internal`)**: Strictly isolated key-vault network (`CA Core` ↔ `SoftHSM2` over PKCS#11).
- **`ai-net` (`--internal`)**: Zero-egress network for local AI services (`Ollama`, `ChromaDB`, `Copilot`, `Chatbot`).

## Build, Run & Verification
1. Initialize the 5 networks:
   ```bash
   bash infra/init-networks.sh

## Step-by-Step Run

# 1. Initialize the 5 isolated Docker bridge networks (NFR-SEC-013, NFR-SEC-014)
bash infra/init-networks.sh

# 2. Build the pinned, non-root Nginx reverse proxy image (NFR-SEC-017, NFR-SEC-018)
docker build -t pqca-nginx:1.0.0 ./images/nginx

# 3. Launch Nginx on frontend-net with read-only rootfs & dropped capabilities
docker run -d \
  --name pqca-nginx \
  --network frontend-net \
  -p 80:8080 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt no-new-privileges:true \
  pqca-nginx:1.0.0

# 4. Bridge Nginx to backend-net for internal FastAPI & OCSP service routing
docker network connect backend-net pqca-nginx

# 5. Verify network segmentation, container attachments, and HTTP health endpoints
bash infra/verify-isolation.sh

# ==============================================================================
# Optional: Clean Teardown (Reset Environment From Scratch)
# ==============================================================================
docker rm -f pqca-nginx
docker network rm frontend-net backend-net db-net hsm-net ai-net