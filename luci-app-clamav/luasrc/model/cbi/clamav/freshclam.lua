-- Freshclam Configuration
-- CBI model for /etc/config/clamav freshclam section

local m, s, o

m = Map("clamav", translate("Freshclam Settings"),
    translate("Configure Freshclam for automatic virus database updates."))

s = m:section(TypedSection, "freshclam", translate("Freshclam Configuration"))
s.anonymous = true
s.addremove = false

-- Config file path
o = s:option(Value, "freshclam_config_file", translate("Freshclam config file"),
    translate("Path to the freshclam configuration file"))
o.default = "/etc/clamav/freshclam.conf"
o.datatype = "string"

-- Logging
o = s:option(Flag, "LogTime", translate("Log time with each message"),
    translate("Log the time with each message"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "LogVerbose", translate("Enable verbose logging"),
    translate("Enable verbose logging for debugging"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "Debug", translate("Debug logging"),
    translate("Enable debug messages"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "LogSyslog", translate("Log to syslog"),
    translate("Use the system logger (syslog)"))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, "LogFacility", translate("Syslog facility"),
    translate("Syslog facility to use"))
o:value("LOG_LOCAL0", "LOG_LOCAL0")
o:value("LOG_LOCAL1", "LOG_LOCAL1")
o:value("LOG_LOCAL2", "LOG_LOCAL2")
o:value("LOG_LOCAL3", "LOG_LOCAL3")
o:value("LOG_LOCAL4", "LOG_LOCAL4")
o:value("LOG_LOCAL5", "LOG_LOCAL5")
o:value("LOG_LOCAL6", "LOG_LOCAL6")
o:value("LOG_LOCAL7", "LOG_LOCAL7")
o:value("LOG_DAEMON", "LOG_DAEMON")
o:value("LOG_MAIL", "LOG_MAIL")
o:value("LOG_USER", "LOG_USER")
o.default = "LOG_LOCAL6"

-- Process
o = s:option(Flag, "Foreground", translate("Run in foreground"),
    translate("Do not fork into background"))
o.default = "0"
o.rmempty = false

o = s:option(Value, "PidFile", translate("PID file"),
    translate("Path to the PID file"))
o.default = "/var/run/clamav/freshclam.pid"
o.datatype = "string"

-- Notification
o = s:option(Flag, "NotifyClamd", translate("Notify clamd"),
    translate("Notify clamd when the database has been updated"))
o.default = "1"
o.rmempty = false

-- Database
o = s:option(Value, "DatabaseOwner", translate("Database owner"),
    translate("Owner of the database files"))
o.default = "nobody"
o.datatype = "string"

o = s:option(Value, "DatabaseDirectory", translate("Database directory"),
    translate("Path to the virus database directory"))
o.default = "/usr/share/clamav"
o.datatype = "directory"

o = s:option(Value, "DNSDatabaseInfo", translate("DNS database info"),
    translate("Use DNS to verify virus database version"))
o.default = "current.cvd.clamav.net"
o.datatype = "string"

o = s:option(Value, "DatabaseMirror", translate("Database mirror"),
    translate("Database mirror server"))
o.default = "database.clamav.net"
o.datatype = "string"

o = s:option(Value, "DatabaseCustomURL", translate("Custom database URL"),
    translate("URL for custom signature database (optional)"))
o.default = ""
o.datatype = "string"
o.optional = true

o = s:option(Value, "PrivateMirror", translate("Private mirror URL"),
    translate("Private mirror for signature updates (optional)"))
o.default = ""
o.datatype = "string"
o.optional = true

-- Update behavior
o = s:option(Flag, "ScriptedUpdates", translate("Scripted updates"),
    translate("Enable scripted updates (cdiff/script-based patching)"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "CompressLocalDatabase", translate("Compress local database"),
    translate("Keep local databases compressed to save disk space"))
o.default = "0"
o.rmempty = false

-- Timeouts
o = s:option(Value, "ConnectTimeout", translate("Connect timeout"),
    translate("Connection timeout in seconds"))
o.datatype = "uinteger"
o.default = "30"

o = s:option(Value, "ReceiveTimeout", translate("Receive timeout"),
    translate("Data receive timeout in seconds"))
o.datatype = "uinteger"
o.default = "60"

-- Update checks
o = s:option(Value, "Checks", translate("Database checks per day"),
    translate("Number of database checks per day (1-50, 0 = disable)"))
o.datatype = "range(0,50)"
o.default = "12"

o = s:option(Flag, "TestDatabases", translate("Test databases"),
    translate("Test databases before installing (recommended)"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "Bytecode", translate("Download bytecode.cvd"),
    translate("Enable downloading of bytecode signatures"))
o.default = "1"
o.rmempty = false

-- Extra/Exclude
o = s:option(DynamicList, "ExtraDatabase", translate("Extra databases"),
    translate("Additional database files or URLs to load"))
o.datatype = "string"
o.optional = true

o = s:option(DynamicList, "ExcludeDatabase", translate("Exclude databases"),
    translate("Database names to exclude from updates"))
o.datatype = "string"
o.optional = true

return m
