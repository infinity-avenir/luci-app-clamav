'use strict';
'require view';
'require form';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('clamav', _('ClamAV Daemon'),
			_('Configure ClamAV daemon (clamd) settings. Changes take effect after saving and restarting the service.'));

		// General Settings
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('General Settings'));
		s.anonymous = false;
		s.addremove = false;

		o = s.option(form.Value, 'ConfigFile', _('Config File'),
			_('Path to the ClamAV configuration file'));
		o.default = '/etc/clamav/clamd.conf';
		o.optional = true;

		// Logging
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('Logging'));

		o = s.option(form.Value, 'LogFile', _('Log File'),
			_('Path to the log file'));
		o.default = '/var/log/clamav/clamd.log';
		o.optional = true;

		o = s.option(form.Flag, 'LogTime', _('Log Timestamps'),
			_('Add timestamps to log messages'));
		o.default = '1';

		o = s.option(form.Flag, 'LogSyslog', _('Log to Syslog'),
			_('Send log messages to syslog'));
		o.default = '0';

		o = s.option(form.ListValue, 'LogFacility', _('Syslog Facility'));
		o.value('LOG_LOCAL0', 'LOG_LOCAL0');
		o.value('LOG_LOCAL1', 'LOG_LOCAL1');
		o.value('LOG_LOCAL2', 'LOG_LOCAL2');
		o.value('LOG_LOCAL6', 'LOG_LOCAL6');
		o.value('LOG_DAEMON', 'LOG_DAEMON');
		o.value('LOG_MAIL', 'LOG_MAIL');
		o.default = 'LOG_LOCAL6';
		o.optional = true;
		o.depends('LogSyslog', '1');

		o = s.option(form.Flag, 'LogVerbose', _('Verbose Logging'),
			_('Enable verbose logging'));
		o.default = '0';

		// Scanning
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('Scanning'));

		o = s.option(form.Value, 'MaxDirectoryRecursion', _('Max Directory Recursion'),
			_('Maximum depth of directory recursion (0 = unlimited)'));
		o.datatype = 'uinteger';
		o.default = '15';

		o = s.option(form.Flag, 'FollowDirectorySymlinks', _('Follow Directory Symlinks'));
		o.default = '0';

		o = s.option(form.Flag, 'FollowFileSymlinks', _('Follow File Symlinks'));
		o.default = '0';

		o = s.option(form.Flag, 'CrossFilesystems', _('Cross Filesystems'),
			_('Scan across filesystem boundaries'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanPE', _('Scan PE'),
			_('Scan Windows PE executables'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanELF', _('Scan ELF'),
			_('Scan Linux ELF executables'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanOLE2', _('Scan OLE2'),
			_('Scan Microsoft Office documents'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanPDF', _('Scan PDF'),
			_('Scan PDF documents'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanSWF', _('Scan SWF'),
			_('Scan Adobe Flash content'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanMail', _('Scan Mail'),
			_('Scan email files'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanHTML', _('Scan HTML'),
			_('Scan HTML files'));
		o.default = '1';

		o = s.option(form.Flag, 'ScanArchive', _('Scan Archives'),
			_('Scan archive files (zip, gz, bz2, etc.)'));
		o.default = '1';

		// Detection
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('Detection'));

		o = s.option(form.Flag, 'DetectPUA', _('Detect PUA'),
			_('Detect Potentially Unwanted Applications'));
		o.default = '0';

		o = s.option(form.Flag, 'DetectBrokenExecutables', _('Detect Broken Executables'),
			_('Alert on broken executable files'));
		o.default = '0';

		o = s.option(form.Flag, 'AlgorithmicDetection', _('Algorithmic Detection'),
			_('Enable heuristic/algorithmic detection'));
		o.default = '1';

		o = s.option(form.Flag, 'HeuristicScanPrecedence', _('Heuristic Precedence'),
			_('Give heuristic alerts higher precedence'));
		o.default = '0';

		// Network
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('Network'));

		o = s.option(form.Value, 'TCPSocket', _('TCP Port'),
			_('TCP port for listening'));
		o.datatype = 'port';
		o.default = '3310';
		o.optional = true;

		o = s.option(form.Value, 'TCPAddr', _('TCP Address'),
			_('IP address to bind to'));
		o.default = '127.0.0.1';
		o.optional = true;

		o = s.option(form.Value, 'MaxConnectionQueueLength', _('Max Connection Queue'),
			_('Maximum number of pending connections'));
		o.datatype = 'uinteger';
		o.default = '15';
		o.optional = true;

		o = s.option(form.Value, 'StreamMinPort', _('Stream Min Port'));
		o.datatype = 'port';
		o.optional = true;

		o = s.option(form.Value, 'StreamMaxPort', _('Stream Max Port'));
		o.datatype = 'port';
		o.optional = true;

		o = s.option(form.Value, 'MaxThreads', _('Max Threads'),
			_('Maximum number of threads'));
		o.datatype = 'uinteger';
		o.default = '10';
		o.optional = true;

		o = s.option(form.Value, 'ReadTimeout', _('Read Timeout'),
			_('Timeout in seconds'));
		o.datatype = 'uinteger';
		o.default = '120';
		o.optional = true;

		o = s.option(form.Value, 'IdleTimeout', _('Idle Timeout'),
			_('Timeout in seconds'));
		o.datatype = 'uinteger';
		o.default = '30';
		o.optional = true;

		// System
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('System'));

		o = s.option(form.Value, 'User', _('Run as User'));
		o.default = 'nobody';
		o.optional = true;

		o = s.option(form.Flag, 'Foreground', _('Foreground'),
			_('Run in foreground (do not daemonize)'));
		o.default = '0';

		o = s.option(form.Value, 'PidFile', _('PID File'));
		o.default = '/var/run/clamav/clamd.pid';
		o.optional = true;

		o = s.option(form.Flag, 'ExitOnOOM', _('Exit on OOM'),
			_('Exit if out of memory'));
		o.default = '0';

		// Directories
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('Directories'));

		o = s.option(form.Value, 'DatabaseDirectory', _('Database Directory'),
			_('Path to virus signature database'));
		o.default = '/usr/share/clamav';
		o.optional = true;

		o = s.option(form.Value, 'TemporaryDirectory', _('Temporary Directory'));
		o.default = '/tmp';
		o.optional = true;

		// Local Socket
		s = m.section(form.NamedSection, 'clamav', 'clamav', _('Local Socket'));

		o = s.option(form.Value, 'LocalSocket', _('Local Socket Path'));
		o.default = '/var/run/clamav/clamd.sock';
		o.optional = true;

		o = s.option(form.Flag, 'FixStaleSocket', _('Fix Stale Socket'),
			_('Remove stale socket files on startup'));
		o.default = '1';

		return m.render();
	}
});
