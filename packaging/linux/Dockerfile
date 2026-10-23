# syntax=docker/dockerfile:1.7

# Node's official binaries are compatible with Ubuntu 24.04. Copying the
# runtime from this stage avoids adding an external apt repository to the
# release build.
FROM node:22-bullseye AS node_runtime

FROM ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG BUILD_ID
ARG AEGIS_ARCH=x64
ARG AEGIS_TARGET=all

COPY --from=node_runtime /usr/local/ /usr/local/

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        dpkg \
        fakeroot \
        file \
        git \
        libarchive-tools \
        libpython3.12 \
        python3 \
        python3-pip \
        python3-venv \
        unzip \
        xz-utils \
        zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache language dependencies independently from application sources.
COPY package.json package-lock.json ./
COPY frontend/package.json frontend/package-lock.json ./frontend/
COPY backend/requirements.txt backend/requirements-dev.txt ./backend/

RUN npm ci --ignore-scripts \
    && npm --prefix frontend ci --ignore-scripts \
    && python3 -m venv backend/.venv \
    && backend/.venv/bin/pip install --no-cache-dir -r backend/requirements-dev.txt

COPY . .

# Validate the native Linux Python environment before freezing it.
RUN npm run test:python \
    && backend/.venv/bin/ruff check backend lab

RUN BUILD_ID="$BUILD_ID" npm run build:ui \
    && BUILD_ID="$BUILD_ID" npm run build:server \
    && if [ "$AEGIS_TARGET" = "all" ]; then \
        set -- AppImage deb tar.gz; \
    else \
        set -- "$AEGIS_TARGET"; \
    fi \
    && npx electron-builder --linux "$@" "--$AEGIS_ARCH" \
        --publish never \
        -c.artifactName="AEGIS-\${version}-${BUILD_ID}-\${arch}.\${ext}"

RUN set -eu; \
    file backend/dist/aegis-server/aegis-server; \
    mkdir -p /release; \
    artifact_count=0; \
    for artifact in dist-electron/*.AppImage dist-electron/*.deb dist-electron/*.tar.gz; do \
        if [ ! -f "$artifact" ]; then continue; fi; \
        file "$artifact"; \
        cp "$artifact" /release/; \
        artifact_count=$((artifact_count + 1)); \
    done; \
    test "$artifact_count" -ge 1; \
    cd /release; \
    sha256sum * > SHA256SUMS

FROM scratch AS artifacts
COPY --from=build /release/ /
