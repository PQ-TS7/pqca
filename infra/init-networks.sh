#!/usr/bin/env bash
set -euo pipefail

# 1. Public-facing edge network (Nginx reverse proxy entry)
docker network create --driver bridge frontend-net || true

# 2. Internal microservice mesh (Nginx <-> FastAPI Gateway, CA Engine, RA, OCSP, CRL)
docker network create --driver bridge --internal backend-net || true

# 3. Database network (Backend services <-> PostgreSQL; no external route)
docker network create --driver bridge --internal db-net || true

# 4. HSM network (Strictly CA Engine <-> SoftHSM2 per NFR-SEC-013 & Q&A Q9)
docker network create --driver bridge --internal hsm-net || true

# 5. AI network (Ollama, ChromaDB, Copilot, Chatbot; zero internet egress per NFR-SEC-014)
docker network create --driver bridge --internal ai-net || true

echo "All 5 PQ-CA isolated networks initialized:"
docker network ls --filter "name=-net"