# OpenSSL 3 + liboqs + oqs-provider base image (ML-DSA-44/65/87).
# Services that do post-quantum crypto build FROM this image.
# Build from the repo root:  docker build -f images/oqs-base/Dockerfile -t pqca/oqs-base:dev .
#
# Everything lives under /opt/openssl; the distro's own libssl is left alone so
# apt, curl, python etc. keep working. Our `openssl` is first on PATH and loads
# oqsprovider through /opt/openssl/ssl/openssl.cnf.

ARG DEBIAN_TAG=trixie-slim
ARG OPENSSL_VERSION=3.5.9
ARG LIBOQS_VERSION=0.16.0
ARG OQSPROVIDER_VERSION=0.12.0

# ---------------------------------------------------------------- builder ---
FROM debian:${DEBIAN_TAG} AS builder
ARG OPENSSL_VERSION
ARG LIBOQS_VERSION
ARG OQSPROVIDER_VERSION

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates cmake git ninja-build perl \
 && rm -rf /var/lib/apt/lists/*

ENV OPENSSL_PREFIX=/opt/openssl
WORKDIR /src

# OpenSSL: shared libs with an rpath so our binary never picks up the distro libssl.
RUN git clone --depth 1 --branch "openssl-${OPENSSL_VERSION}" https://github.com/openssl/openssl.git \
 && cd openssl \
 && ./Configure --prefix="${OPENSSL_PREFIX}" --openssldir="${OPENSSL_PREFIX}/ssl" --libdir=lib \
      shared no-docs no-tests "-Wl,-rpath,${OPENSSL_PREFIX}/lib" \
 && make -j"$(nproc)" \
 && make install_sw install_ssldirs

# liboqs: static + PIC so it is linked into oqsprovider.so (nothing extra to ship).
# OQS_DIST_BUILD keeps CPU-feature dispatch at runtime, so the image runs on any x86-64/arm64 node.
RUN git clone --depth 1 --branch "${LIBOQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git \
 && cmake -S liboqs -B liboqs/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
      -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
      -DOQS_USE_OPENSSL=ON \
      -DOPENSSL_ROOT_DIR="${OPENSSL_PREFIX}" \
 && cmake --build liboqs/build \
 && cmake --install liboqs/build

RUN git clone --depth 1 --branch "${OQSPROVIDER_VERSION}" https://github.com/open-quantum-safe/oqs-provider.git \
 && cmake -S oqs-provider -B oqs-provider/build -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR="${OPENSSL_PREFIX}" \
      -Dliboqs_DIR=/opt/liboqs/lib/cmake/liboqs \
 && cmake --build oqs-provider/build \
 && install -D -m 0644 oqs-provider/build/lib/oqsprovider.so "${OPENSSL_PREFIX}/lib/ossl-modules/oqsprovider.so"

# ---------------------------------------------------------------- runtime ---
FROM debian:${DEBIAN_TAG}
ARG OPENSSL_VERSION
ARG LIBOQS_VERSION
ARG OQSPROVIDER_VERSION

LABEL org.opencontainers.image.title="pqca/oqs-base" \
      org.opencontainers.image.description="OpenSSL ${OPENSSL_VERSION} + liboqs ${LIBOQS_VERSION} + oqs-provider ${OQSPROVIDER_VERSION} (ML-DSA)" \
      pqca.openssl.version="${OPENSSL_VERSION}" \
      pqca.liboqs.version="${LIBOQS_VERSION}" \
      pqca.oqsprovider.version="${OQSPROVIDER_VERSION}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/openssl /opt/openssl
COPY images/oqs-base/openssl.cnf /opt/openssl/ssl/openssl.cnf
COPY --chmod=0755 images/oqs-base/oqs-selftest.sh /usr/local/bin/oqs-selftest

ENV PATH=/opt/openssl/bin:${PATH} \
    OPENSSL_MODULES=/opt/openssl/lib/ossl-modules

# Fail the build if ML-DSA isn't usable end to end.
RUN oqs-selftest

RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin pqca
USER pqca
WORKDIR /tmp
CMD ["openssl", "version", "-a"]
