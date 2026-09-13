-- LuCI ClamAV Controller
-- Copyright 2024 Spark Secure
-- Licensed under the Apache License, Version 2.0

module("luci.controller.clamav", package.seeall)

function index()
    -- Main entry: Services -> ClamAV
    entry({"admin", "services", "clamav"}, alias("admin", "services", "clamav", "status"), _("ClamAV"), 65)

    -- Status dashboard
    entry({"admin", "services", "clamav", "status"}, template("clamav/status"), _("Status"), 10)

    -- Configuration tabs
    entry({"admin", "services", "clamav", "clamd"}, cbi("clamav/clamd"), _("ClamAV Settings"), 20)
    entry({"admin", "services", "clamav", "milter"}, cbi("clamav/milter"), _("Milter Settings"), 30)
    entry({"admin", "services", "clamav", "freshclam"}, cbi("clamav/freshclam"), _("Freshclam Settings"), 40)

    -- Alerts page
    entry({"admin", "services", "clamav", "alerts"}, template("clamav/alerts"), _("Alerts"), 50)

    -- Signature update page
    entry({"admin", "services", "clamav", "signatures"}, template("clamav/signatures"), _("Signatures"), 60)

    -- Quarantine page
    entry({"admin", "services", "clamav", "quarantine"}, template("clamav/quarantine"), _("Quarantine"), 70)

    -- API endpoints for AJAX
    entry({"admin", "services", "clamav", "api", "status"}, call("api_status")).leaf = true
    entry({"admin", "services", "clamav", "api", "alerts"}, call("api_alerts")).leaf = true
    entry({"admin", "services", "clamav", "api", "scan"}, call("api_scan"), nil, nil).leaf = true
    entry({"admin", "services", "clamav", "api", "update_sigs"}, call("api_update_sigs"), nil, nil).leaf = true
    entry({"admin", "services", "clamav", "api", "quarantine"}, call("api_quarantine")).leaf = true
    entry({"admin", "services", "clamav", "api", "service"}, call("api_service"), nil, nil).leaf = true
end

-- Helper: execute a command and return output
local function exec(cmd)
    local handle = io.popen(cmd .. " 2>/dev/null")
    if not handle then return "" end
    local result = handle:read("*a")
    handle:close()
    return result or ""
end

-- Helper: get ClamAV service status
local function get_service_status()
    local status = {}

    -- Check if clamd is running
    local pid = exec("pidof clamd"):match("(%d+)")
    status.running = pid ~= nil
    status.pid = pid or "N/A"

    -- Memory usage
    if pid then
        local mem = exec("cat /proc/" .. pid .. "/status 2>/dev/null | grep VmRSS")
        status.memory = mem:match("(%d+)") or "0"
        status.memory = tonumber(status.memory) or 0
    else
        status.memory = 0
    end

    -- System memory
    local meminfo = exec("cat /proc/meminfo")
    status.mem_total = tonumber(meminfo:match("MemTotal:%s+(%d+)")) or 0
    status.mem_free = tonumber(meminfo:match("MemFree:%s+(%d+)")) or 0
    status.mem_available = tonumber(meminfo:match("MemAvailable:%s+(%d+)")) or 0

    -- ClamAV version
    status.version = exec("clamd --version 2>/dev/null"):match("ClamAV%s+([%d%.]+)") or "Unknown"

    -- Database info
    local db_dir = exec("uci -q get clamav.clamd.DatabaseDirectory") or "/usr/share/clamav"
    db_dir = db_dir:gsub("%s+$", "")
    if db_dir == "" then db_dir = "/usr/share/clamav" end

    local db_files = exec("ls -la " .. db_dir .. "/*.cvd " .. db_dir .. "/*.cld 2>/dev/null")
    status.db_files = db_files
    status.db_dir = db_dir

    -- Signature count
    local sig_count = exec("sigtool --count-sigs " .. db_dir .. " 2>/dev/null"):match("(%d+)")
    status.signatures = sig_count or "N/A"

    -- Last database update time
    local last_update = exec("stat -c '%Y' " .. db_dir .. "/daily.cvd 2>/dev/null " ..
        "|| stat -c '%Y' " .. db_dir .. "/daily.cld 2>/dev/null")
    status.last_db_update = last_update:gsub("%s+$", "")

    -- Uptime
    if pid then
        local elapsed = exec("ps -o etimes= -p " .. pid)
        status.uptime = tonumber(elapsed:match("(%d+)")) or 0
    else
        status.uptime = 0
    end

    -- Check freshclam status
    local freshclam_pid = exec("pidof freshclam"):match("(%d+)")
    status.freshclam_running = freshclam_pid ~= nil

    -- Check milter status
    local milter_pid = exec("pidof clamav-milter"):match("(%d+)")
    status.milter_running = milter_pid ~= nil

    -- Alert count from log
    local alert_count = exec("grep -c 'FOUND' /var/log/clamav/clamd.log 2>/dev/null " ..
        "|| grep -c 'FOUND' /tmp/clamd.log 2>/dev/null " ..
        "|| echo 0")
    status.alert_count = tonumber(alert_count:match("(%d+)")) or 0

    return status
end

-- API: Get current status (JSON)
function api_status()
    local json = require "luci.jsonc"
    local http = require "luci.http"

    http.prepare_content("application/json")
    local status = get_service_status()
    http.write(json.stringify(status))
end

-- API: Get recent alerts (JSON)
function api_alerts()
    local json = require "luci.jsonc"
    local http = require "luci.http"

    http.prepare_content("application/json")

    local alerts = {}
    -- Parse clamd log for FOUND entries
    local log_output = exec(
        "grep 'FOUND\\|ERROR\\|WARNING' /var/log/clamav/clamd.log 2>/dev/null " ..
        "|| grep 'FOUND\\|ERROR\\|WARNING' /tmp/clamd.log 2>/dev/null " ..
        "|| echo ''"
    )

    local count = 0
    for line in log_output:gmatch("[^\n]+") do
        if count < 50 then
            local entry = {}
            entry.timestamp = line:match("^(%S+ %S+)") or ""
            entry.message = line
            if line:match("FOUND") then
                entry.severity = "danger"
                entry.type = "Virus Found"
                entry.file = line:match(":%s*(.-):%s*%S+%s+FOUND") or ""
                entry.virus = line:match(":%s+(%S+)%s+FOUND") or ""
            elseif line:match("ERROR") then
                entry.severity = "warning"
                entry.type = "Error"
            else
                entry.severity = "info"
                entry.type = "Warning"
            end
            table.insert(alerts, 1, entry)
            count = count + 1
        end
    end

    -- Also pull from syslog
    local syslog = exec("logread 2>/dev/null | grep -i 'clam' | tail -20")
    for line in syslog:gmatch("[^\n]+") do
        if count < 50 then
            local entry = {}
            entry.timestamp = line:match("^(%S+ %S+ %S+ %S+)") or ""
            entry.message = line
            if line:match("FOUND") then
                entry.severity = "danger"
                entry.type = "Virus Found"
            elseif line:match("[Ee]rror") then
                entry.severity = "warning"
                entry.type = "Error"
            else
                entry.severity = "info"
                entry.type = "Info"
            end
            table.insert(alerts, entry)
            count = count + 1
        end
    end

    http.write(json.stringify({ alerts = alerts, total = count }))
end

-- API: Trigger a scan
function api_scan()
    local http = require "luci.http"
    local json = require "luci.jsonc"
    local path = http.formvalue("path") or "/tmp"

    http.prepare_content("application/json")

    -- Use clamdscan for efficiency
    local result = exec("clamdscan --no-summary " .. path .. " 2>&1 | head -100")
    local infected = exec("clamdscan " .. path .. " 2>&1 | grep 'Infected files'")
    local count = infected:match("(%d+)") or "0"

    http.write(json.stringify({
        output = result,
        infected = tonumber(count) or 0,
        path = path
    }))
end

-- API: Update signatures
function api_update_sigs()
    local http = require "luci.http"
    local json = require "luci.jsonc"

    http.prepare_content("application/json")

    local result = exec("freshclam 2>&1")
    local success = not result:match("ERROR")

    http.write(json.stringify({
        success = success,
        output = result
    }))
end

-- API: List quarantined files
function api_quarantine()
    local http = require "luci.http"
    local json = require "luci.jsonc"

    http.prepare_content("application/json")

    local quarantine_dir = exec("uci -q get clamav.clamd.quarantine_dir"):gsub("%s+$", "")
    if quarantine_dir == "" then quarantine_dir = "/tmp/clamav-quarantine" end

    local files = {}
    local listing = exec("ls -la " .. quarantine_dir .. " 2>/dev/null")
    for line in listing:gmatch("[^\n]+") do
        local perms, _, owner, group, size, month, day, time_or_year, name =
            line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(.+)$")
        if name and name ~= "." and name ~= ".." then
            table.insert(files, {
                name = name,
                size = size,
                date = month .. " " .. day .. " " .. time_or_year,
                owner = owner
            })
        end
    end

    http.write(json.stringify({
        directory = quarantine_dir,
        files = files,
        count = #files
    }))
end

-- API: Start/Stop/Restart service
function api_service()
    local http = require "luci.http"
    local json = require "luci.jsonc"
    local action = http.formvalue("action") or "status"

    http.prepare_content("application/json")

    local result = ""
    local success = false

    if action == "start" then
        result = exec("/etc/init.d/clamav start 2>&1")
        success = true
    elseif action == "stop" then
        result = exec("/etc/init.d/clamav stop 2>&1")
        success = true
    elseif action == "restart" then
        result = exec("/etc/init.d/clamav restart 2>&1")
        success = true
    elseif action == "enable" then
        result = exec("/etc/init.d/clamav enable 2>&1")
        success = true
    elseif action == "disable" then
        result = exec("/etc/init.d/clamav disable 2>&1")
        success = true
    end

    http.write(json.stringify({
        success = success,
        action = action,
        output = result
    }))
end
