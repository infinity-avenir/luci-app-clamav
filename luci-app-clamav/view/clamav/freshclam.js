'use strict';
'require view';
'require form';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('clamav', _('Freshclam'),
			_('Configure ClamAV signature updater (freshclam) settings.'));

		// General
		s = m.section(form.NamedSection, 'freshclam', 'freshclam', _('General Settings'));
		s.anonymous = false;
		s.addremove = false;

		o = s.option(form.Value, 'ConfigFile', _('Config File'));
		o.default = '/etc/clamav/freshclam.conf';
		o.optional = true;

		o = s.option(form.Flag, 'Foreground', _('Foreground'),
			_('Run in foreground'));
		o.default = '0';

		o = s.option(form.Value, 'PidFile', _('PID File'));
		o.default = '/var/run/clamav/freshclam.pid';
		o.optional = true;

		// Logging
		s = m.section(form.NamedSection, 'freshclam', 'freshclam', _('Logging'));

		o = s.option(form.Value, 'UpdateLogFile', _('Log File'));
		o.default = '/var/log/clamav/freshclam.log';
		o.optional = true;

		o = s.option(form.Flag, 'LogTime', _('Log Timestamps'));
		o.default = '1';

		o = s.option(form.Flag, 'LogSyslog', _('Log to Syslog'));
		o.default = '0';

		o = s.option(form.Flag, 'LogVerbose', _('Verbose Logging'));
		o.default = '0';

		// Update Settings
		s = m.section(form.NamedSection, 'freshclam', 'freshclam', _('Update Settings'));

		o = s.option(form.Value, 'DatabaseOwner', _('Database Owner'),
			_('Owner of the database files'));
		o.default = 'nobody';
		o.optional = true;

		o = s.option(form.Value, 'DatabaseDirectory', _('Database Directory'));
		o.default = '/usr/share/clamav';
		o.optional = true;

		o = s.option(form.Value, 'DatabaseMirror', _('Database Mirror'),
			_('Signature update mirror'));
		o.default = 'database.clamav.net';
		o.optional = true;

		o = s.option(form.DynamicList, 'DatabaseCustomURL', _('Custom Database URLs'),
			_('Additional custom signature databases'));
		o.optional = true;

		o = s.option(form.Value, 'PrivateMirror', _('Private Mirror'),
			_('Private mirror for signature updates'));
		o.optional = true;

		o = s.option(form.Value, 'DNSDatabaseInfo', _('DNS Database Info'));
		o.default = 'current.cvd.clamav.net';
		o.optional = true;

		o = s.option(form.ListValue, 'Checks', _('Update Frequency'),
			_('How often freshclam checks for signature updates'));
		o.value('12', _('Every 2 hours'));
		o.value('6', _('Every 4 hours'));
		o.value('3', _('Every 8 hours'));
		o.value('2', _('Every 12 hours'));
		o.value('1', _('Every 24 hours'));
		o.default = '1';

		o = s.option(form.Flag, 'ScriptedUpdates', _('Scripted Updates'),
			_('Use incremental (scripted) updates'));
		o.default = '1';

		o = s.option(form.Flag, 'CompressLocalDatabase', _('Compress Local Database'));
		o.default = '0';

		o = s.option(form.Flag, 'TestDatabases', _('Test Databases'),
			_('Test databases after update'));
		o.default = '1';

		o = s.option(form.Flag, 'Bytecode', _('Bytecode'),
			_('Enable bytecode signatures'));
		o.default = '1';

		// Network
		s = m.section(form.NamedSection, 'freshclam', 'freshclam', _('Network'));

		o = s.option(form.Value, 'ConnectTimeout', _('Connect Timeout'),
			_('Connection timeout in seconds'));
		o.datatype = 'uinteger';
		o.default = '30';
		o.optional = true;

		o = s.option(form.Value, 'ReceiveTimeout', _('Receive Timeout'),
			_('Data receive timeout in seconds'));
		o.datatype = 'uinteger';
		o.default = '30';
		o.optional = true;

		// Notification
		s = m.section(form.NamedSection, 'freshclam', 'freshclam', _('Notification'));

		o = s.option(form.Value, 'NotifyClamd', _('Notify ClamD'),
			_('Path to clamd config to notify after update'));
		o.default = '/etc/clamav/clamd.conf';
		o.optional = true;

		// Extra databases
		s = m.section(form.NamedSection, 'freshclam', 'freshclam', _('Extra Databases'));

		o = s.option(form.DynamicList, 'ExtraDatabase', _('Extra Databases'),
			_('Additional databases to load'));
		o.optional = true;

		o = s.option(form.DynamicList, 'ExcludeDatabase', _('Exclude Databases'),
			_('Databases to exclude'));
		o.optional = true;

		return m.render();
	}
});
