'use strict';
'require view';
'require dom';
'require poll';
'require uci';
'require rpc';
'require fs';

var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: ['name', 'action'],
	expect: { result: false }
});

var callInitList = rpc.declare({
	object: 'luci',
	method: 'getInitList',
	params: ['name'],
	expect: { '': {} }
});

/* Parse CVD/CLD header */
function parseCvdInfo(raw) {
	var dbs = [];
	var lines = raw.trim().split('\n');
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i].trim();
		if (!line) continue;
		var sep = line.indexOf('|');
		if (sep === -1) continue;
		var fname = line.substring(0, sep);
		var header = line.substring(sep + 1);
		var fields = header.split(':');
		if (fields.length >= 4 && fields[0] === 'ClamAV-VDB') {
			dbs.push({
				name: fname,
				version: parseInt(fields[2]) || 0,
				sigs: parseInt(fields[3]) || 0,
				buildTime: fields[1] || ''
			});
		}
	}
	return dbs;
}

/* Detect database directory from UCI or freshclam.conf */
function getDbDir() {
	var uciDir = uci.get('clamav', 'clamav', 'DatabaseDirectory');
	if (uciDir) return uciDir.replace(/\/+$/, '');
	return null;
}

function renderStatus(container) {
	return uci.load('clamav').then(function() {
		var dbDir = getDbDir();
		var dbDirPromise;

		if (dbDir) {
			dbDirPromise = Promise.resolve(dbDir);
		} else {
			dbDirPromise = fs.exec('/bin/sh', ['-c',
				"grep -m1 '^DatabaseDirectory' /etc/clamav/freshclam.conf 2>/dev/null | awk '{print $2}'"
			]).then(function(res) {
				var dir = (res && res.stdout || '').trim();
				return dir || '/usr/share/clamav';
			}).catch(function() {
				return '/usr/share/clamav';
			});
		}

		return dbDirPromise;
	}).then(function(dbDir) {
		return Promise.all([
			fs.exec('/bin/ps', ['w']),
			fs.exec('/bin/cat', ['/proc/meminfo']).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/sh', ['-c',
				'chmod 644 ' + dbDir + '/*.cvd ' + dbDir + '/*.cld 2>/dev/null; ' +
				'for f in ' + dbDir + '/*.cvd ' + dbDir + '/*.cld; do ' +
				'[ -f "$f" ] && echo "$(basename "$f")|$(dd if="$f" bs=512 count=1 2>/dev/null | tr -d "\\000")"; done'
			]).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/grep', ['-c', 'FOUND', '/var/log/clamav/clamd.log']).catch(function() { return { stdout: '0' }; }),
			callInitList('clamav'),
			fs.exec('/bin/sh', ['-c', 'clamdscan --version 2>/dev/null || clamd --version 2>/dev/null']).catch(function() { return { stdout: '' }; }),
			Promise.resolve(dbDir)
		]);
	}).then(function(data) {
		var psOut = (data[0] && data[0].stdout) || '';
		var memOut = (data[1] && data[1].stdout) || '';
		var cvdRaw = (data[2] && data[2].stdout) || '';
		var alertStr = (data[3] && data[3].stdout) || '0';
		var initInfo = data[4] || {};
		var versionOut = (data[5] && data[5].stdout) || '';
		var dbDir = data[6];

		var clamdRunning = psOut.indexOf('clamd') !== -1 && psOut.indexOf('grep') === -1;
		var freshclamRunning = psOut.indexOf('freshclam') !== -1;
		var clamdEnabled = initInfo.clamav ? initInfo.clamav.enabled : false;

		var alertCount = parseInt(alertStr.trim()) || 0;

		var memTotal = 0, memAvail = 0;
		var memLines = memOut.split('\n');
		for (var i = 0; i < memLines.length; i++) {
			var m = memLines[i].match(/^MemTotal:\s+(\d+)/);
			if (m) memTotal = parseInt(m[1]);
			m = memLines[i].match(/^MemAvailable:\s+(\d+)/);
			if (m) memAvail = parseInt(m[1]);
		}
		var memUsedPct = memTotal > 0 ? Math.round(((memTotal - memAvail) / memTotal) * 100) : 0;

		var dbs = parseCvdInfo(cvdRaw);
		var totalSigs = 0;
		for (var j = 0; j < dbs.length; j++) {
			totalSigs += dbs[j].sigs;
		}

		var statusColor = clamdRunning ? '#22c55e' : '#ef4444';
		var statusText = clamdRunning ? _('Running') : _('Stopped');
		var memColor = memUsedPct < 60 ? '#22c55e' : (memUsedPct < 80 ? '#f59e0b' : '#ef4444');

		var dbDetailRows = [];
		for (var k = 0; k < dbs.length; k++) {
			dbDetailRows.push(
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'color:#6b7280;padding-left:24px' }, dbs[k].name),
					E('td', { 'class': 'td' },
						dbs[k].sigs.toLocaleString() + _(' sigs') +
						' (v' + dbs[k].version + ')' +
						(dbs[k].buildTime ? ' — ' + dbs[k].buildTime : ''))
				])
			);
		}

		dom.content(container, E('div', { 'style': 'max-width:900px' }, [
			E('h2', { 'style': 'margin-bottom:16px' }, _('ClamAV Status')),

			E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px' }, [
				E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
					E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('ClamAV Daemon')),
					E('div', { 'style': 'font-size:20px;font-weight:600;color:' + statusColor }, statusText)
				]),
				E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
					E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Freshclam')),
					E('div', { 'style': 'font-size:20px;font-weight:600;color:' + (freshclamRunning ? '#22c55e' : '#6b7280') },
						freshclamRunning ? _('Running') : _('Stopped'))
				]),
				E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
					E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Signatures')),
					E('div', { 'style': 'font-size:20px;font-weight:600;color:#3b82f6' },
						totalSigs > 0 ? totalSigs.toLocaleString() : '—')
				]),
				E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
					E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Alerts')),
					E('div', { 'style': 'font-size:20px;font-weight:600;color:' + (alertCount > 0 ? '#ef4444' : '#22c55e') },
						String(alertCount))
				])
			]),

			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:20px' }, [
				E('div', { 'style': 'display:flex;justify-content:space-between;margin-bottom:8px' }, [
					E('span', { 'style': 'font-size:13px;color:#6b7280' }, _('System Memory')),
					E('span', { 'style': 'font-size:13px;font-weight:600' }, memUsedPct + '%')
				]),
				E('div', { 'style': 'background:#e5e7eb;border-radius:4px;height:8px;overflow:hidden' }, [
					E('div', { 'style': 'background:' + memColor + ';height:100%;width:' + memUsedPct + '%;border-radius:4px;transition:width 0.3s' })
				])
			]),

			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:20px' }, [
				E('div', { 'style': 'font-size:14px;font-weight:600;margin-bottom:12px' }, _('Service Control')),
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap' }, [
					E('button', {
						'class': 'cbi-button cbi-button-apply',
						'click': function() {
							callInitAction('clamav', 'start').then(function() { renderStatus(container); });
						}
					}, _('Start')),
					E('button', {
						'class': 'cbi-button cbi-button-reset',
						'click': function() {
							callInitAction('clamav', 'stop').then(function() { renderStatus(container); });
						}
					}, _('Stop')),
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'click': function() {
							callInitAction('clamav', 'restart').then(function() { renderStatus(container); });
						}
					}, _('Restart')),
					E('button', {
						'class': 'cbi-button',
						'click': function() {
							var act = clamdEnabled ? 'disable' : 'enable';
							callInitAction('clamav', act).then(function() { renderStatus(container); });
						}
					}, clamdEnabled ? _('Disable') : _('Enable'))
				])
			]),

			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px' }, [
				E('div', { 'style': 'font-size:14px;font-weight:600;margin-bottom:12px' }, _('Details')),
				E('table', { 'class': 'table', 'style': 'width:100%' }, [
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'width:40%;color:#6b7280' }, _('Daemon Status')),
						E('td', { 'class': 'td' }, statusText)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Autostart')),
						E('td', { 'class': 'td' }, clamdEnabled ? _('Enabled') : _('Disabled'))
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Freshclam Status')),
						E('td', { 'class': 'td' }, freshclamRunning ? _('Running') : _('Stopped'))
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Memory Usage')),
						E('td', { 'class': 'td' }, memUsedPct + '% (' + Math.round((memTotal - memAvail) / 1024) + ' MB / ' + Math.round(memTotal / 1024) + ' MB)')
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Database Directory')),
						E('td', { 'class': 'td', 'style': 'font-family:monospace;font-size:13px' }, dbDir)
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Total Signatures')),
						E('td', { 'class': 'td', 'style': 'font-weight:600' },
							totalSigs > 0 ? totalSigs.toLocaleString() : _('No databases loaded'))
					])
				].concat(dbDetailRows).concat([
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Alerts Detected')),
						E('td', { 'class': 'td' }, String(alertCount))
					]),
					E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Engine Version')),
						E('td', { 'class': 'td' }, versionOut.trim() || _('Unknown'))
					])
				]))
			])
		]));
	});
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	render: function() {
		var container = E('div');
		renderStatus(container);

		poll.add(function() {
			return renderStatus(container);
		}, 5);

		return container;
	}
});
