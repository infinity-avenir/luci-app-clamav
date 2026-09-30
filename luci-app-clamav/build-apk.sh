#!/bin/bash
# Build script for luci-app-clamav — JS-based LuCI module
# APK v2 format with PAX checksums for apk-tools 3.x

set -e

PKG_NAME="luci-app-clamav"
PKG_VERSION="1.0.0-r15"
PKG_ARCH="noarch"

SRC_DIR="/home/claude/luci-app-clamav-js"
BUILD_DIR="/home/claude/build-apk-v6"
OUTPUT_DIR="/home/claude/output"

echo "=== Building ${PKG_NAME}-${PKG_VERSION} (JS-based LuCI module) ==="

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/control" "${BUILD_DIR}/data" "${OUTPUT_DIR}"

# ============================================================
# 1. Populate data tree (modern LuCI JS structure)
# ============================================================

# Menu definition
mkdir -p "${BUILD_DIR}/data/usr/share/luci/menu.d"
cp "${SRC_DIR}/menu.d/luci-app-clamav.json" \
   "${BUILD_DIR}/data/usr/share/luci/menu.d/luci-app-clamav.json"

# ACL definition
mkdir -p "${BUILD_DIR}/data/usr/share/rpcd/acl.d"
cp "${SRC_DIR}/acl.d/luci-app-clamav.json" \
   "${BUILD_DIR}/data/usr/share/rpcd/acl.d/luci-app-clamav.json"

# JavaScript views
mkdir -p "${BUILD_DIR}/data/www/luci-static/resources/view/clamav"
for f in status.js clamd.js freshclam.js milter.js alerts.js signatures.js quarantine.js; do
    cp "${SRC_DIR}/view/clamav/${f}" \
       "${BUILD_DIR}/data/www/luci-static/resources/view/clamav/${f}"
done

# UCI defaults
mkdir -p "${BUILD_DIR}/data/etc/uci-defaults"
cp "${SRC_DIR}/uci-defaults/40_luci-clamav" \
   "${BUILD_DIR}/data/etc/uci-defaults/40_luci-clamav"
chmod +x "${BUILD_DIR}/data/etc/uci-defaults/40_luci-clamav"

# ============================================================
# 2. Calculate installed size
# ============================================================
INSTALLED_SIZE=$(du -sb "${BUILD_DIR}/data" | cut -f1)
BUILD_TIME=$(date +%s)

# ============================================================
# 3. Build data segment (PAX format + SHA1 checksums)
# ============================================================
echo "Creating data segment..."

python3 << 'PYEOF'
import tarfile, io, os, gzip, hashlib

BUILD_DIR = os.environ.get("BUILD_DIR", "/home/claude/build-apk-v6")
data_dir = os.path.join(BUILD_DIR, "data")

buf = io.BytesIO()
tar = tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT)

for root, dirs, files in sorted(os.walk(data_dir)):
    relpath = os.path.relpath(root, data_dir)
    if relpath == '.':
        continue
    arcname = relpath + '/'

    ti = tar.gettarinfo(root, arcname=arcname)
    ti.uid = 0
    ti.gid = 0
    ti.uname = 'root'
    ti.gname = 'root'
    tar.addfile(ti)

    for fname in sorted(files):
        fpath = os.path.join(root, fname)
        arcname = os.path.relpath(fpath, data_dir)
        ti = tar.gettarinfo(fpath, arcname=arcname)
        ti.uid = 0
        ti.gid = 0
        ti.uname = 'root'
        ti.gname = 'root'

        sha1 = hashlib.sha1()
        with open(fpath, 'rb') as f:
            sha1.update(f.read())
        ti.pax_headers = {'APK-TOOLS.checksum.SHA1': sha1.hexdigest()}

        with open(fpath, 'rb') as f:
            tar.addfile(ti, f)

tar.close()
raw_tar = buf.getvalue()

data_gz_path = os.path.join(BUILD_DIR, "data_segment.tar.gz")
with open(data_gz_path, 'wb') as f:
    gz = gzip.GzipFile(fileobj=f, mode='wb', mtime=0)
    gz.write(raw_tar)
    gz.close()

print(f"Data segment: {len(raw_tar)} bytes tar -> {os.path.getsize(data_gz_path)} bytes gzipped")
PYEOF

# ============================================================
# 4. Compute datahash
# ============================================================
DATA_HASH=$(sha256sum "${BUILD_DIR}/data_segment.tar.gz" | cut -d' ' -f1)
echo "Data segment SHA256: ${DATA_HASH}"

# ============================================================
# 5. Create .PKGINFO
# ============================================================
cat > "${BUILD_DIR}/control/.PKGINFO" << EOF
pkgname = ${PKG_NAME}
pkgver = ${PKG_VERSION}
pkgdesc = LuCI web interface for ClamAV antivirus management
url = https://github.com/spark-secure/luci-app-clamav
builddate = ${BUILD_TIME}
packager = Spark Secure <alan@spark-secure.com>
size = ${INSTALLED_SIZE}
arch = ${PKG_ARCH}
license = Apache-2.0
depend = luci-base
depend = clamav
datahash = ${DATA_HASH}
maintainer = Spark Secure <alan@spark-secure.com>
EOF

# ============================================================
# 6. Create install scripts
# ============================================================
cat > "${BUILD_DIR}/control/.post-install" << 'SCRIPT'
#!/bin/sh
if [ -f /etc/uci-defaults/40_luci-clamav ]; then
    ( . /etc/uci-defaults/40_luci-clamav ) && rm -f /etc/uci-defaults/40_luci-clamav
fi
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/
# Restart rpcd to pick up new ACL definitions
/etc/init.d/rpcd restart 2>/dev/null || true
exit 0
SCRIPT
chmod +x "${BUILD_DIR}/control/.post-install"

cat > "${BUILD_DIR}/control/.post-deinstall" << 'SCRIPT'
#!/bin/sh
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/
exit 0
SCRIPT
chmod +x "${BUILD_DIR}/control/.post-deinstall"

# ============================================================
# 7. Build control segment (USTAR, no end-of-archive)
# ============================================================
echo "Creating control segment..."

python3 << 'PYEOF'
import tarfile, io, os, gzip

BUILD_DIR = os.environ.get("BUILD_DIR", "/home/claude/build-apk-v6")
control_dir = os.path.join(BUILD_DIR, "control")

buf = io.BytesIO()
tar = tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT)

for fname in ['.PKGINFO', '.post-install', '.post-deinstall']:
    fpath = os.path.join(control_dir, fname)
    ti = tar.gettarinfo(fpath, arcname=fname)
    ti.uid = 0
    ti.gid = 0
    ti.uname = 'root'
    ti.gname = 'root'
    with open(fpath, 'rb') as f:
        tar.addfile(ti, f)

buf.flush()
raw_tar = buf.getvalue()

control_gz_path = os.path.join(BUILD_DIR, "control_segment.tar.gz")
with open(control_gz_path, 'wb') as f:
    gz = gzip.GzipFile(fileobj=f, mode='wb', mtime=0)
    gz.write(raw_tar)
    gz.close()

print(f"Control segment: {len(raw_tar)} bytes tar -> {os.path.getsize(control_gz_path)} bytes gzipped")
PYEOF

# ============================================================
# 8. Assemble APK
# ============================================================
echo "Assembling APK..."
cat "${BUILD_DIR}/control_segment.tar.gz" \
    "${BUILD_DIR}/data_segment.tar.gz" \
    > "${OUTPUT_DIR}/${PKG_NAME}-${PKG_VERSION}.apk"

echo ""
echo "=== Build Complete ==="
ls -lh "${OUTPUT_DIR}/${PKG_NAME}-${PKG_VERSION}.apk"
echo ""
echo "--- Installed files ---"
find "${BUILD_DIR}/data" -type f | sed "s|${BUILD_DIR}/data/||" | sort
