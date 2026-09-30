# luci-app-clamav

LuCI web interface for ClamAV antivirus management on OpenWrt routers.

**Version:** 1.0.0-r15  
**Architecture:** noarch (pure JavaScript — works on any OpenWrt router)  
**License:** Apache-2.0  

## Features

- **Status** — Live dashboard: daemon status, freshclam status, signature count, alert count, memory usage, service start/stop/restart/enable/disable
- **ClamAV Settings** — Full clamd configuration: logging, scanning options, detection, network, system, directories, local socket
- **Freshclam Settings** — Signature updater config: update frequency dropdown, mirrors, database options, network timeouts
- **ClamAV Milter** — Mail filter settings: sockets, actions (on clean/infected/fail), limits, logging
- **Alerts** — Threat log viewer with summary cards, alert table, and raw log tail
- **Signatures** — Database manager: per-database download/update with background execution and progress polling, auto-update frequency display, storage & engine info
- **Quarantine** — Quarantine file viewer with delete actions

## Source Tree

```
luci-app-clamav/
├── acl.d/
│   └── luci-app-clamav.json        # rpcd ACL definitions
├── menu.d/
│   └── luci-app-clamav.json        # LuCI menu structure (7 tabs)
├── uci-defaults/
│   └── 40_luci-clamav               # First-install UCI config setup
├── view/clamav/
│   ├── status.js                    # Status dashboard
│   ├── clamd.js                     # ClamAV daemon settings
│   ├── freshclam.js                 # Freshclam settings
│   ├── milter.js                    # Mail filter settings
│   ├── alerts.js                    # Alert management
│   ├── signatures.js                # Signature database management
│   └── quarantine.js                # Quarantine management
├── build-apk.sh                     # APK build script
└── README.md                        # This file
```

## Install Methods

### Method 1: Install Pre-built APK

Transfer the APK to your router and install:

```sh
# Copy APK to router (from your build machine)
scp luci-app-clamav-1.0.0-r15.apk root@<router-ip>:/tmp/

# Install on router
apk add --allow-untrusted /tmp/luci-app-clamav-1.0.0-r15.apk
```

The `--allow-untrusted` flag is needed because the package is not signed with an OpenWrt repository key. This is normal for locally-built packages.

### Method 2: Install from Source (manual copy)

Copy the source files directly to the router without building an APK:

```sh
# Copy files to router
scp acl.d/luci-app-clamav.json   root@<router-ip>:/usr/share/rpcd/acl.d/luci-app-clamav.json
scp menu.d/luci-app-clamav.json  root@<router-ip>:/usr/share/luci/menu.d/luci-app-clamav.json

scp view/clamav/status.js        root@<router-ip>:/www/luci-static/resources/view/clamav/status.js
scp view/clamav/clamd.js         root@<router-ip>:/www/luci-static/resources/view/clamav/clamd.js
scp view/clamav/freshclam.js     root@<router-ip>:/www/luci-static/resources/view/clamav/freshclam.js
scp view/clamav/milter.js        root@<router-ip>:/www/luci-static/resources/view/clamav/milter.js
scp view/clamav/alerts.js        root@<router-ip>:/www/luci-static/resources/view/clamav/alerts.js
scp view/clamav/signatures.js    root@<router-ip>:/www/luci-static/resources/view/clamav/signatures.js
scp view/clamav/quarantine.js    root@<router-ip>:/www/luci-static/resources/view/clamav/quarantine.js

scp uci-defaults/40_luci-clamav  root@<router-ip>:/etc/uci-defaults/40_luci-clamav
```

Then SSH into the router and run:

```sh
# Create directories (if they don't exist)
mkdir -p /usr/share/rpcd/acl.d
mkdir -p /usr/share/luci/menu.d
mkdir -p /www/luci-static/resources/view/clamav
mkdir -p /etc/uci-defaults

# Run UCI defaults (creates initial config if not present)
chmod +x /etc/uci-defaults/40_luci-clamav
sh /etc/uci-defaults/40_luci-clamav && rm -f /etc/uci-defaults/40_luci-clamav

# Clear LuCI cache and restart rpcd
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/
/etc/init.d/rpcd restart
```

### Method 3: One-liner Install from Source via SSH

SSH into the router first, then paste this block:

```sh
# Create all directories
mkdir -p /usr/share/rpcd/acl.d \
         /usr/share/luci/menu.d \
         /www/luci-static/resources/view/clamav \
         /etc/uci-defaults \
         /var/log/clamav \
         /var/run/clamav \
         /tmp/clamav-quarantine

# Clear cache and restart rpcd to pick up ACLs
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/
/etc/init.d/rpcd restart 2>/dev/null || true
```

Then use scp to copy the files (from your build machine):

```sh
ROUTER="root@<router-ip>"
scp acl.d/luci-app-clamav.json   ${ROUTER}:/usr/share/rpcd/acl.d/
scp menu.d/luci-app-clamav.json  ${ROUTER}:/usr/share/luci/menu.d/
scp view/clamav/*.js              ${ROUTER}:/www/luci-static/resources/view/clamav/
scp uci-defaults/40_luci-clamav  ${ROUTER}:/etc/uci-defaults/
ssh ${ROUTER} 'chmod +x /etc/uci-defaults/40_luci-clamav && sh /etc/uci-defaults/40_luci-clamav && rm -f /etc/uci-defaults/40_luci-clamav && rm -f /tmp/luci-indexcache && rm -rf /tmp/luci-modulecache/ && /etc/init.d/rpcd restart 2>/dev/null'
```

## Build APK from Source

### Prerequisites

On your build machine (Linux, macOS, or WSL):

- `bash`
- `python3`
- `gzip`
- `sha256sum` (or `shasum` on macOS)

### Build

```sh
chmod +x build-apk.sh
./build-apk.sh
```

Output: `output/luci-app-clamav-1.0.0-r15.apk`

The build script creates an Alpine APK v2 package with:
- PAX-format data segment with SHA1 checksums per file
- USTAR-format control segment with .PKGINFO, .post-install, .post-deinstall
- Proper datahash linking control to data

## Dependencies

- `luci-base` — OpenWrt LuCI web interface
- `clamav` — ClamAV antivirus engine

## Uninstall

```sh
# If installed via APK:
apk del luci-app-clamav

# If installed from source:
rm -f /usr/share/rpcd/acl.d/luci-app-clamav.json
rm -f /usr/share/luci/menu.d/luci-app-clamav.json
rm -rf /www/luci-static/resources/view/clamav/
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/
/etc/init.d/rpcd restart
```

## Troubleshooting

### ClamAV config path mismatch

If ClamAV was compiled with default paths at `/usr/etc/` but OpenWrt puts configs at `/etc/clamav/`, create symlinks:

```sh
mkdir -p /usr/etc
ln -sf /etc/clamav/clamd.conf /usr/etc/clamd.conf
ln -sf /etc/clamav/freshclam.conf /usr/etc/freshclam.conf
```

### Database "Not Installed" despite files on disk

Ensure database files are readable:

```sh
chmod 644 /path/to/your/db/*.cvd /path/to/your/db/*.cld
```

### clamd won't start (out of memory)

On routers with ~1 GB RAM or less, clamd may not be able to load all 3.6M+ signatures into memory. Use `clamscan` (on-demand scanning) instead — it loads signatures per scan then releases memory.
