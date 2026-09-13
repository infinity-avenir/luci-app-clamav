-- ClamAV (clamd) Configuration
-- CBI model for /etc/config/clamav clamd section

local m, s, o

m = Map("clamav", translate("ClamAV Settings"),
    translate("Configure the ClamAV daemon (clamd). Changes require a service restart to take effect."))

s = m:section(TypedSection, "clamd", translate("ClamAV Daemon Configuration"))
s.anonymous = true
s.addremove = false

-- Config file path
o = s:option(Value, "clamd_config_file", translate("clamd config file"),
    translate("Path to the clamd configuration file"))
o.default = "/etc/clamav/clamd.conf"
o.datatype = "string"

-- Logging
o = s:option(Flag, "LogTime", translate("Log time with each message"),
    translate("Log the time with each message"))
o.default = "1"
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

o = s:option(Flag, "LogVerbose", translate("Log additional infection info"),
    translate("Enable verbose logging of infection details"))
o.default = "0"
o.rmempty = false

-- Scanning
o = s:option(Value, "MaxDirectoryRecursion", translate("Max directory scan depth"),
    translate("Maximum depth for directory recursion (0 = unlimited)"))
o.datatype = "uinteger"
o.default = "15"

o = s:option(Flag, "FollowDirectorySymlinks", translate("Follow directory symlinks"),
    translate("Follow directory symlinks during scanning"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "FollowFileSymlinks", translate("Follow file symlinks"),
    translate("Follow regular file symlinks during scanning"))
o.default = "0"
o.rmempty = false

-- Detection
o = s:option(Flag, "DetectPUA", translate("Detect possibly unwanted apps"),
    translate("Detect Possibly Unwanted Applications (PUA)"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "ScanPE", translate("Scan portable executables"),
    translate("PE stands for Portable Executable - the format used by Windows executables"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "ScanELF", translate("Scan ELF files"),
    translate("Scan ELF (Linux/Unix executable) files"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "DetectBrokenExecutables", translate("Detect broken executables"),
    translate("Mark broken executables as potentially harmful"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "AlertBrokenExecutables", translate("Alert on broken executables"),
    translate("Alert when a broken executable is found"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "ScanOLE2", translate("Scan MS Office and .msi files"),
    translate("Scan Microsoft Office documents and Windows Installer files"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "ScanPDF", translate("Scan PDF files"),
    translate("Scan PDF files for embedded content"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "ScanSWF", translate("Scan SWF files"),
    translate("Scan Adobe Flash (SWF) files"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "ScanMail", translate("Scan emails"),
    translate("Scan mail files for embedded malware"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "ScanPartialMessages", translate("Scan RFC1341 messages split over many emails"),
    translate("Scan RFC1341 partial messages (split across multiple emails)"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "ScanArchive", translate("Scan archives"),
    translate("Scan archive files (zip, rar, gz, etc.)"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, "BlockEncrypted", translate("Block encrypted archives"),
    translate("Block encrypted archives as potentially harmful"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "AlertEncrypted", translate("Alert on encrypted archives"),
    translate("Generate an alert when an encrypted archive is encountered"))
o.default = "0"
o.rmempty = false

-- Network
o = s:option(Value, "StreamMinPort", translate("Port range, lowest port"),
    translate("Lowest port number for data streaming"))
o.datatype = "port"
o.default = "1024"

o = s:option(Value, "StreamMaxPort", translate("Port range, highest port"),
    translate("Highest port number for data streaming"))
o.datatype = "port"
o.default = "2048"

o = s:option(Value, "ReadTimeout", translate("Read timeout"),
    translate("Read timeout in seconds (0 = unlimited)"))
o.datatype = "uinteger"
o.default = "120"

o = s:option(Value, "CommandReadTimeout", translate("Command read timeout"),
    translate("Command read timeout in seconds (0 = unlimited)"))
o.datatype = "uinteger"
o.default = "10"

-- Performance
o = s:option(Value, "MaxThreads", translate("Max number of threads"),
    translate("Maximum number of threads for scanning"))
o.datatype = "uinteger"
o.default = "2"

o = s:option(Value, "SelfCheck", translate("Database check every N sec"),
    translate("Check for database updates at this interval in seconds"))
o.datatype = "uinteger"
o.default = "600"

o = s:option(Value, "MaxFileSize", translate("Max size of scanned file"),
    translate("Maximum file size to scan (in bytes, 0 = unlimited). Suffixes: K, M"))
o.default = "25M"
o.datatype = "string"

-- TCP
o = s:option(Value, "TCPAddr", translate("TCP listen address"),
    translate("TCP address to listen on (0.0.0.0 for all interfaces)"))
o.default = "127.0.0.1"
o.datatype = "ipaddr"

o = s:option(Value, "TCPSocket", translate("TCP listen port"),
    translate("TCP port to listen on"))
o.datatype = "port"
o.default = "3310"

-- System
o = s:option(Value, "User", translate("User"),
    translate("Run clamd as this user"))
o.default = "nobody"
o.datatype = "string"

o = s:option(Flag, "ExitOnOOM", translate("Exit when Out Of Memory"),
    translate("Exit clamd when system runs out of memory"))
o.default = "0"
o.rmempty = false

o = s:option(Flag, "DisableCertCheck", translate("Disable certificate checks"),
    translate("Disable certificate verification for database downloads"))
o.default = "0"
o.rmempty = false

-- Directories
o = s:option(Value, "DatabaseDirectory", translate("Database directory"),
    translate("Path to the virus database directory"))
o.default = "/usr/share/clamav"
o.datatype = "directory"

o = s:option(Value, "TemporaryDirectory", translate("Temporary directory"),
    translate("Path to the temporary directory for scanning"))
o.default = "/tmp"
o.datatype = "directory"

o = s:option(Value, "LocalSocket", translate("Local socket"),
    translate("Path to the local Unix socket"))
o.default = "/var/run/clamav/clamd.sock"
o.datatype = "string"

return m
