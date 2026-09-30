'use strict';
'require view';
'require form';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('clamav', _('ClamAV Milter'),
			_('Configure ClamAV Milter (mail filter) settings.'));

		// General
		s = m.section(form.NamedSection, 'milter', 'milter', _('General Settings'));
		s.anonymous = false;
		s.addremove = false;

		o = s.option(form.Value, 'ConfigFile', _('Config File'));
		o.default = '/etc/clamav/clamav-milter.conf';
		o.optional = true;

		o = s.option(form.Flag, 'Foreground', _('Foreground'),
			_('Run in foreground'));
		o.default = '0';

		o = s.option(form.Value, 'PidFile', _('PID File'));
		o.default = '/var/run/clamav/clamav-milter.pid';
		o.optional = true;

		o = s.option(form.Value, 'User', _('Run as User'));
		o.default = 'nobody';
		o.optional = true;

		o = s.option(form.Value, 'MilterSocketGroup', _('Socket Group'));
		o.optional = true;

		// Sockets
		s = m.section(form.NamedSection, 'milter', 'milter', _('Sockets'));

		o = s.option(form.Value, 'MilterSocket', _('Milter Socket'),
			_('Socket to receive mail data'));
		o.default = '/var/run/clamav/clamav-milter.sock';
		o.optional = true;

		o = s.option(form.Value, 'ClamdSocket', _('ClamD Socket'),
			_('Socket to communicate with clamd'));
		o.default = 'unix:/var/run/clamav/clamd.sock';
		o.optional = true;

		o = s.option(form.Flag, 'FixStaleSocket', _('Fix Stale Socket'),
			_('Remove stale socket files on startup'));
		o.default = '1';

		// Actions
		s = m.section(form.NamedSection, 'milter', 'milter', _('Actions'));

		o = s.option(form.ListValue, 'OnClean', _('On Clean'),
			_('Action when message is clean'));
		o.value('Accept', _('Accept'));
		o.value('Reject', _('Reject'));
		o.value('Defer', _('Defer'));
		o.value('Blackhole', _('Blackhole'));
		o.value('Quarantine', _('Quarantine'));
		o.default = 'Accept';

		o = s.option(form.ListValue, 'OnInfected', _('On Infected'),
			_('Action when virus is found'));
		o.value('Reject', _('Reject'));
		o.value('Quarantine', _('Quarantine'));
		o.value('Blackhole', _('Blackhole'));
		o.value('Defer', _('Defer'));
		o.value('Accept', _('Accept'));
		o.default = 'Quarantine';

		o = s.option(form.ListValue, 'OnFail', _('On Fail'),
			_('Action when scanning fails'));
		o.value('Defer', _('Defer'));
		o.value('Accept', _('Accept'));
		o.value('Reject', _('Reject'));
		o.value('Blackhole', _('Blackhole'));
		o.default = 'Defer';

		o = s.option(form.Value, 'RejectMsg', _('Reject Message'),
			_('Custom rejection message'));
		o.optional = true;

		o = s.option(form.Flag, 'AddHeader', _('Add Header'),
			_('Add X-Virus-Scanned header to messages'));
		o.default = '1';

		// Timeouts
		s = m.section(form.NamedSection, 'milter', 'milter', _('Timeouts'));

		o = s.option(form.Value, 'ReadTimeout', _('Read Timeout'),
			_('Timeout for reading data in seconds'));
		o.datatype = 'uinteger';
		o.default = '120';
		o.optional = true;

		// Logging
		s = m.section(form.NamedSection, 'milter', 'milter', _('Logging'));

		o = s.option(form.Value, 'LogFile', _('Log File'));
		o.default = '/var/log/clamav/clamav-milter.log';
		o.optional = true;

		o = s.option(form.Flag, 'LogTime', _('Log Timestamps'));
		o.default = '1';

		o = s.option(form.Flag, 'LogSyslog', _('Log to Syslog'));
		o.default = '0';

		o = s.option(form.Flag, 'LogVerbose', _('Verbose Logging'));
		o.default = '0';

		// Limits
		s = m.section(form.NamedSection, 'milter', 'milter', _('Limits'));

		o = s.option(form.Value, 'MaxFileSize', _('Max File Size'),
			_('Maximum file size to scan (e.g. 25M)'));
		o.default = '25M';
		o.optional = true;

		o = s.option(form.Flag, 'SupportMultipleRecipients', _('Support Multiple Recipients'));
		o.default = '0';

		o = s.option(form.Value, 'TemporaryDirectory', _('Temporary Directory'));
		o.default = '/tmp';
		o.optional = true;

		return m.render();
	}
});
