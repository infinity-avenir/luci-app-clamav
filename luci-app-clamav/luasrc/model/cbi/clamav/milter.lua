-- ClamAV Milter Configuration
-- CBI model for /etc/config/clamav milter section

local m, s, o

m = Map("clamav", translate("ClamAV Milter Settings"),
    translate("Configure the ClamAV Milter daemon for email filtering integration."))

s = m:section(TypedSection, "milter", translate("ClamAV Milter Configuration"))
s.anonymous = true
s.addremove = false

-- Config file path
o = s:option(Value, "milter_config_file", translate("clamav-milter config file"),
    translate("Path to the clamav-milter configuration file"))
o.default = "/etc/clamav/clamav-milter.conf"
o.datatype = "string"

-- Process
o = s:option(Flag, "Foreground", translate("Run in foreground"),
    translate("Do not fork into background"))
o.default = "0"
o.rmempty = false

o = s:option(Value, "PidFile", translate("PID file"),
    translate("Path to the PID file"))
o.default = "/var/run/clamav/clamav-milter.pid"
o.datatype = "string"

o = s:option(Value, "User", translate("User"),
    translate("Run clamav-milter as this user"))
o.default = "nobody"
o.datatype = "string"

o = s:option(Value, "MilterSocketGroup", translate("Milter socket group"),
    translate("Group for the milter Unix socket"))
o.default = "clamav"
o.datatype = "string"

-- Timeouts
o = s:option(Value, "ReadTimeout", translate("Read timeout"),
    translate("Read timeout in seconds"))
o.datatype = "uinteger"
o.default = "120"

-- Actions
o = s:option(ListValue, "OnClean", translate("On-clean action"),
    translate("Action to take when a message is clean"))
o:value("Accept", translate("Accept"))
o:value("Reject", translate("Reject"))
o:value("Defer", translate("Defer"))
o:value("Blackhole", translate("Blackhole"))
o:value("Quarantine", translate("Quarantine"))
o.default = "Accept"

o = s:option(ListValue, "OnInfected", translate("On-infected action"),
    translate("Action to take when a message is infected"))
o:value("Reject", translate("Reject"))
o:value("Accept", translate("Accept"))
o:value("Defer", translate("Defer"))
o:value("Blackhole", translate("Blackhole"))
o:value("Quarantine", translate("Quarantine"))
o.default = "Quarantine"

o = s:option(ListValue, "OnFail", translate("On-fail action"),
    translate("Action to take when scanning fails"))
o:value("Defer", translate("Defer"))
o:value("Accept", translate("Accept"))
o:value("Reject", translate("Reject"))
o:value("Blackhole", translate("Blackhole"))
o:value("Quarantine", translate("Quarantine"))
o.default = "Defer"

o = s:option(ListValue, "AddHeader", translate("Add header"),
    translate("Add an X-Virus-Scanned / X-Virus-Status header to messages"))
o:value("Replace", translate("Replace"))
o:value("Yes", translate("Yes"))
o:value("No", translate("No"))
o:value("Add", translate("Add"))
o.default = "Replace"

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
    translate("Enable debug messages from libclamav"))
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

o = s:option(Flag, "LogInfected", translate("Log infections"),
    translate("Log infected messages"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "LogClean", translate("Log clean"),
    translate("Log clean messages"))
o.default = "0"
o.rmempty = false

-- Scanning
o = s:option(Value, "MaxFileSize", translate("Max size of scanned file"),
    translate("Maximum file size to scan (in bytes, 0 = unlimited). Suffixes: K, M"))
o.default = "25M"
o.datatype = "string"

o = s:option(Flag, "SupportMultipleRecipients", translate("Support multiple recipients"),
    translate("Support messages with multiple recipients"))
o.default = "0"
o.rmempty = false

-- Rejection
o = s:option(Value, "RejectMsg", translate("Rejection log message"),
    translate("Custom rejection message for infected emails"))
o.default = ""
o.datatype = "string"
o.placeholder = "Rejecting Harmful Email: %v found."

o = s:option(Value, "VirusAction", translate("Rejecting Harmful Email: %v found."),
    translate("External command to execute when a virus is found. %v is replaced with virus name."))
o.default = ""
o.datatype = "string"

-- Directories / Sockets
o = s:option(Value, "TemporaryDirectory", translate("Temporary directory"),
    translate("Path to the temporary directory"))
o.default = "/tmp"
o.datatype = "directory"

o = s:option(Value, "MilterSocket", translate("Local socket"),
    translate("Path to the milter Unix socket"))
o.default = "/var/run/clamav/clamav-milter.sock"
o.datatype = "string"

o = s:option(Value, "ClamdSocket", translate("clamd socket"),
    translate("Path to the clamd socket to connect to"))
o.default = "unix:/var/run/clamav/clamd.sock"
o.datatype = "string"

o = s:option(Flag, "FixStaleSocket", translate("Fix stale socket"),
    translate("Remove stale socket files before creating new ones"))
o.default = "1"
o.rmempty = false

return m
