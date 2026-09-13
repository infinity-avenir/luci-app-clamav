# LuCI ClamAV — Web Interface for ClamAV on OpenWrt

A complete LuCI web interface module for managing ClamAV antivirus directly from your OpenWrt router's administration panel.

**Version:** 1.0.0  
**License:** Apache 2.0  


---

## Features

### Real-time Status Dashboard
- Service status indicator (running / stopped) with PID
- ClamAV daemon memory usage with visual progress bar
- System memory monitoring (total, free, available)
- Virus signature count and last database update time
- Freshclam and Milter sub-service status badges
- Alert counter (total threats detected)
- Quick Scan — enter any path and scan on demand from the browser

### Complete Configuration Interface
Three dedicated settings pages, each backed by UCI (`/etc/config/clamav`):

**ClamAV Settings (clamd)** — 30+ options including config file path, logging (syslog, facility, verbose), scanning controls (PE, ELF, OLE2, PDF, SWF, mail, archives), detection settings (PUA, broken executables, encrypted archives), network (TCP address/port, streaming port range, timeouts, threads), system (user, OOM behavior, certificate checks), and paths (database, temp, local socket).

**ClamAV Milter Settings** — Email filtering integration: config path, foreground/PID/user/socket-group, read timeout, on-clean/on-infected/on-fail actions, header insertion, full logging controls, max file size, multi-recipient support, rejection message template, temp directory, milter and clamd sockets, stale socket handling.

**Freshclam Settings** — Automatic signature updates: config path, logging controls, foreground/PID, clamd notification, database owner/directory, DNS verification, mirror/custom URL/private mirror, scripted updates, compression, timeouts, checks per day, database testing, bytecode downloads, extra/exclude database lists.

### Alert Management
- View the last 50 alerts from clamd log and syslog
- Color-coded severity badges (virus/error/info)
- Per-alert file path and threat name when available
- Summary statistics (viruses, errors, info counts)
- Auto-refresh every 5 seconds (toggle on/off)

### Signature Update Management
- Database file listing with sizes and dates
- Total signature count
- Freshclam status check
- One-click "Update Now" with live output

### Quarantine Management
- List all quarantined files with name, size, date, owner
- Quarantine directory path display
- File count badge

---

## Project Structure

```
luci-app-clamav/
├── Makefile                              # OpenWrt package Makefile
├── luasrc/
│   ├── controller/
│   │   └── clamav.lua                    # LuCI controller — routes & API
│   ├── model/
│   │   └── cbi/
│   │       └── clamav/
│   │           ├── clamd.lua             # CBI model: ClamAV daemon settings
│   │           ├── milter.lua            # CBI model: Milter settings
│   │           └── freshclam.lua         # CBI model: Freshclam settings
│   └── view/
│       └── clamav/
│           ├── status.htm                # Status dashboard template
│           ├── alerts.htm                # Alert management template
│           ├── signatures.htm            # Signature management template
│           └── quarantine.htm            # Quarantine viewer template
└── root/
    └── etc/
        ├── config/
        │   └── clamav                    # UCI default config
        └── uci-defaults/
            └── 40_luci-clamav            # Post-install setup script
```

---

## Detailed Code Explanation

### 1. Controller (`luasrc/controller/clamav.lua`)

The controller is the routing backbone. It registers every page under `admin > services > clamav` in the LuCI menu tree.

**Menu entries** — `index()` defines seven page routes:
- `status` → HTM template (the dashboard)
- `clamd`, `milter`, `freshclam` → CBI models (form-based settings pages)
- `alerts`, `signatures`, `quarantine` → HTM templates (read-only views)

**API endpoints** — Six JSON API handlers support the AJAX-driven views:
- `api_status` — Collects live data: reads `/proc/<pid>/status` for clamd memory, `/proc/meminfo` for system RAM, runs `sigtool --count-sigs` for signature count, `stat` for last database update timestamp, `pidof` for all three service PIDs.
- `api_alerts` — Parses clamd's log file for lines containing `FOUND`, `ERROR`, or `WARNING`, extracts file paths and virus names from FOUND lines, and also pulls ClamAV-related entries from `logread` (OpenWrt's syslog ring buffer). Returns the 50 most recent, newest first.
- `api_scan` — Runs `clamdscan` on a user-supplied path and returns both the line-by-line output and the infected file count.
- `api_update_sigs` — Executes `freshclam` and returns its output plus a success/failure flag.
- `api_quarantine` — Lists the quarantine directory (configurable via UCI) with file metadata.
- `api_service` — Calls `/etc/init.d/clamav start|stop|restart|enable|disable`.

Helper `exec(cmd)` wraps `io.popen` for all shell calls, appending `2>/dev/null` to suppress stderr.

### 2. CBI Models (`luasrc/model/cbi/clamav/*.lua`)

CBI (Configuration Bind Interface) is LuCI's form-generation framework. Each model file declares a `Map` bound to the `clamav` UCI config and a `TypedSection` targeting one config section (`clamd`, `milter`, or `freshclam`).

**Option types used:**
- `Flag` — boolean toggle, rendered as a checkbox. Maps to UCI `0`/`1`.
- `Value` — text input. `datatype` validates on save (e.g., `uinteger`, `port`, `ipaddr`, `directory`).
- `ListValue` — dropdown select. Values are added with `:value()`.
- `DynamicList` — repeatable text inputs, used for Freshclam's extra/exclude database lists.

Every option has a `translate()` label and description, a sensible `default`, and `rmempty = false` where the setting must always be present in the config file.

When a user clicks "Save & Apply", LuCI writes the values back to `/etc/config/clamav` using UCI, and the init script reads them to generate the native ClamAV config files.

### 3. View Templates (`luasrc/view/clamav/*.htm`)

Each HTM file is a LuCI template wrapped in `<%+header%>` / `<%+footer%>` (which inject the LuCI page chrome — sidebar, CSS, topbar).

**status.htm** — The dashboard. Four summary cards (service status, memory, signatures, alerts) at the top, then action buttons (Start/Stop/Restart/Refresh), a details table, and a Quick Scan input box. JavaScript function `refreshStatus()` fires an XHR to the `api/status` endpoint every 5 seconds and updates the DOM. The memory progress bar changes color at 60% (orange) and 80% (red).

**alerts.htm** — Three statistic cards at the top, then a full-width table. `loadAlerts()` fetches from `api/alerts` and dynamically renders rows with severity badges. Auto-refresh is togglable.

**signatures.htm** — Database info table, a file list section, and an "Update Now" button. The update button disables itself during the request, shows live output in a monospace box, and reloads info after completion.

**quarantine.htm** — Simple file table pulled from `api/quarantine`, showing name, size, date, and owner.

All views use inline `<style>` blocks with a clean white theme. Colors are minimal: green for healthy, red for threats, orange for warnings, grey for inactive.

### 4. UCI Config (`root/etc/config/clamav`)

The UCI config file is the single source of truth. It contains three named sections:
- `config clamd 'clamd'` — all clamd options
- `config milter 'milter'` — all milter options
- `config freshclam 'freshclam'` — all freshclam options

Every option corresponds exactly to a CBI model field. When the ClamAV init script runs, it reads this file and generates the native `.conf` files that clamd/milter/freshclam actually consume.

### 5. UCI Defaults Script (`root/etc/uci-defaults/40_luci-clamav`)

Runs once at first boot after installation. It creates the quarantine directory (`/tmp/clamav-quarantine`) and the runtime socket directory (`/var/run/clamav`), then clears LuCI's index cache so the new menu entries appear immediately.

### 6. OpenWrt Makefile

Standard LuCI package Makefile. It declares:
- `LUCI_DEPENDS:=+luci-base +clamav` — requires LuCI and ClamAV to be installed.
- `LUCI_PKGARCH:=all` — architecture-independent (pure Lua/HTML).
- Includes `luci.mk` which handles installing files from `luasrc/` and `root/` into the correct locations.

---

## Installation Guide

### Prerequisites
- OpenWrt 21.02 or later (with LuCI installed)
- ClamAV installed on the router (`opkg install clamav` or equivalent)
- SSH access to the router

### Method 1: Install from APK/IPK file (recommended)

1. **Transfer the package to your router:**
   ```bash
   scp luci-app-clamav_1.0.0-1_all.apk root@192.168.1.1:/tmp/
   ```

2. **SSH into the router and install:**
   ```bash
   ssh root@192.168.1.1

   # For OpenWrt 24.x+ (APK-based):
   apk add --allow-untrusted /tmp/luci-app-clamav_1.0.0-1_all.apk

   # For OpenWrt 21.x–23.x (opkg-based):
   opkg install /tmp/luci-app-clamav_1.0.0-1_all.ipk
   ```

3. **Clear the LuCI cache (usually done automatically):**
   ```bash
   rm -f /tmp/luci-indexcache
   rm -rf /tmp/luci-modulecache/
   ```

4. **Access the interface:**  
   Open your browser and navigate to:  
   `http://192.168.1.1/cgi-bin/luci/admin/services/clamav`  
   Or go to **Services → ClamAV** in the LuCI menu.

### Method 2: Manual file installation

1. **Copy files to the router:**
   ```bash
   # Controller
   scp luasrc/controller/clamav.lua \
       root@192.168.1.1:/usr/lib/lua/luci/controller/

   # CBI models
   ssh root@192.168.1.1 "mkdir -p /usr/lib/lua/luci/model/cbi/clamav"
   scp luasrc/model/cbi/clamav/*.lua \
       root@192.168.1.1:/usr/lib/lua/luci/model/cbi/clamav/

   # View templates
   ssh root@192.168.1.1 "mkdir -p /usr/lib/lua/luci/view/clamav"
   scp luasrc/view/clamav/*.htm \
       root@192.168.1.1:/usr/lib/lua/luci/view/clamav/

   # UCI config
   scp root/etc/config/clamav \
       root@192.168.1.1:/etc/config/clamav
   ```

2. **Create required directories on the router:**
   ```bash
   ssh root@192.168.1.1
   mkdir -p /tmp/clamav-quarantine /var/run/clamav
   rm -f /tmp/luci-indexcache
   rm -rf /tmp/luci-modulecache/
   ```

3. **Refresh the browser and navigate to Services → ClamAV.**

### Method 3: Build with the OpenWrt SDK

1. Place the `luci-app-clamav` directory inside your OpenWrt source tree:
   ```bash
   cp -r luci-app-clamav/ openwrt/package/feeds/luci/
   ```

2. Update feeds and select the package:
   ```bash
   cd openwrt
   ./scripts/feeds update luci
   ./scripts/feeds install luci-app-clamav
   make menuconfig
   # Navigate to LuCI → Applications → luci-app-clamav, press 'M'
   ```

3. Build the package:
   ```bash
   make package/feeds/luci/luci-app-clamav/compile V=s
   ```

4. Find the output in `bin/packages/*/luci/`.

### Uninstallation

```bash
# APK-based (OpenWrt 24.x+):
apk del luci-app-clamav

# opkg-based:
opkg remove luci-app-clamav

# Clear cache:
rm -f /tmp/luci-indexcache
rm -rf /tmp/luci-modulecache/
```

---

## Configuration Notes

- All settings are stored in `/etc/config/clamav` using the UCI system.
- Changes made through the LuCI interface are written to UCI. Your ClamAV init script should read these values and generate the native config files (e.g., `/etc/clamav/clamd.conf`).
- If your ClamAV installation uses a custom init script, ensure it reads from UCI or adapt it accordingly.
- The quarantine directory defaults to `/tmp/clamav-quarantine`. On devices with limited flash storage, `/tmp` (tmpfs/RAM) is preferred.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Menu entry doesn't appear | `rm -f /tmp/luci-indexcache && rm -rf /tmp/luci-modulecache/` then refresh |
| Status shows "Stopped" | Ensure ClamAV is installed and the init script is enabled: `/etc/init.d/clamav enable && /etc/init.d/clamav start` |
| "Permission denied" errors | Check that clamd runs as the user specified in settings; ensure socket directories exist and are writable |
| Signature update fails | Check network connectivity; verify `freshclam.conf` or UCI `DatabaseMirror` points to a reachable server |
| High memory usage | ClamAV is memory-intensive; on routers with <256MB RAM, consider reducing `MaxThreads` to 1 and lowering `MaxFileSize` |
