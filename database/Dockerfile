# PostgreSQL with the PQ-CA schema. The init scripts run once, on an empty volume.
# Build from the repo root:  docker build -f database/Dockerfile -t pqca/database:dev .
ARG POSTGRES_VERSION=16
FROM postgres:${POSTGRES_VERSION}
COPY --chmod=0755 database/init/ /docker-entrypoint-initdb.d/
