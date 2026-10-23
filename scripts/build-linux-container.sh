#!/bin/bash
# Build native Ubuntu packages from macOS or Linux without contaminating the
# workspace with Linux node_modules or Python virtual environments.
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AEGIS_ARCH="${1:-x64}"
AEGIS_TARGET="${2:-all}"
BUILD_ID="${BUILD_ID:-$(date +%Y%m%d-%H%M)}"
if [[ "$AEGIS_TARGET" == "all" ]]; then
    OUTPUT_SUFFIX=""
else
    OUTPUT_SUFFIX="-$AEGIS_TARGET"
fi
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_ROOT/dist-linux/$AEGIS_ARCH-$BUILD_ID$OUTPUT_SUFFIX}"

case "$AEGIS_ARCH" in
    x64)
        PLATFORM="linux/amd64"
        ;;
    arm64)
        PLATFORM="linux/arm64"
        ;;
    *)
        echo "Usage: $0 [x64|arm64] [all|deb|AppImage|tar.gz]"
        exit 2
        ;;
esac

case "$AEGIS_TARGET" in
    all|deb|AppImage|tar.gz)
        ;;
    *)
        echo "Usage: $0 [x64|arm64] [all|deb|AppImage|tar.gz]"
        exit 2
        ;;
esac

mkdir -p "$OUTPUT_DIR"

echo "Building AEGIS for Ubuntu ($AEGIS_ARCH) in $PLATFORM"
echo "Target: $AEGIS_TARGET"
echo "Build ID: $BUILD_ID"
echo "Output: $OUTPUT_DIR"

docker buildx build \
    --platform "$PLATFORM" \
    --file "$SCRIPT_ROOT/packaging/linux/Dockerfile" \
    --build-arg "BUILD_ID=$BUILD_ID" \
    --build-arg "AEGIS_ARCH=$AEGIS_ARCH" \
    --build-arg "AEGIS_TARGET=$AEGIS_TARGET" \
    --target artifacts \
    --output "type=local,dest=$OUTPUT_DIR" \
    "$SCRIPT_ROOT"

echo "Linux artifacts ready:"
ls -lh "$OUTPUT_DIR"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUTPUT_DIR" && sha256sum --check SHA256SUMS)
else
    (cd "$OUTPUT_DIR" && shasum -a 256 --check SHA256SUMS)
fi
