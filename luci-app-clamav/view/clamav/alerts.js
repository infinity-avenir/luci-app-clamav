'use strict';
'require view';
'require dom';
'require poll';
'require fs';
'require ui';

function parseAlerts(logText) {
	var alerts = [];
	var lines = logText.split('\n');
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i];
		if (line.indexOf('FOUND') === -1) continue;

		// Format: "/path/to/file: ThreatName FOUND"
		var match = line.match(/^(.*?):\s+(.*?)\s+FOUND\s*$/);
		if (match) {
			// Try to extract timestamp from syslog-style prefix
			var tsMatch = line.match(/^(\w+\s+\d+\s+[\d:]+\s+\d{4})/);
			alerts.push({
				file: match[1].replace(/^.*?\]\s*/, '').trim(),
				threat: match[2],
				timestamp: tsMatch ? tsMatch[1] : '',
				raw: line
			});
		}
	}
	return alerts.reverse(); // newest first
}

function renderAlerts(container) {
	return Promise.all([
		fs.exec('/bin/cat', ['/var/log/clamav/clamd.log']).catch(function() { return { stdout: '' }; }),
		fs.exec('/usr/bin/find', ['/tmp/clamav-quarantine', '-type', 'f']).catch(function() { return { stdout: '' }; })
	]).then(function(data) {
		var logOut = (data[0] && data[0].stdout) || '';
		var quarantined = ((data[1] && data[1].stdout) || '').trim().split('\n').filter(function(f) { return f.length > 0; });
		var alerts = parseAlerts(logOut);

		var children = [
			E('h2', { 'style': 'margin-bottom:16px' }, _('Alert Management'))
		];

		// Summary card
		children.push(E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px' }, [
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Total Alerts')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:' + (alerts.length > 0 ? '#ef4444' : '#22c55e') },
					String(alerts.length))
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Quarantined Files')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:#f59e0b' },
					String(quarantined.length))
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Unique Threats')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:#8b5cf6' },
					String(alerts.reduce(function(acc, a) { if (acc.indexOf(a.threat) === -1) acc.push(a.threat); return acc; }, []).length))
			])
		]));

		// Alert table
		if (alerts.length > 0) {
			var rows = [
				E('tr', { 'class': 'tr' }, [
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Threat')),
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('File')),
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Timestamp'))
				])
			];

			var shown = Math.min(alerts.length, 100);
			for (var i = 0; i < shown; i++) {
				var a = alerts[i];
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'padding:8px 12px;color:#ef4444;font-weight:500;word-break:break-all' }, a.threat),
					E('td', { 'class': 'td', 'style': 'padding:8px 12px;font-family:monospace;font-size:12px;word-break:break-all' }, a.file),
					E('td', { 'class': 'td', 'style': 'padding:8px 12px;white-space:nowrap;color:#6b7280' }, a.timestamp || '—')
				]));
			}

			if (alerts.length > 100) {
				rows.push(E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'colspan': '3', 'style': 'padding:8px 12px;color:#6b7280;text-align:center' },
						_('Showing 100 of %d alerts').format(alerts.length))
				]));
			}

			children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:20px' }, [
				E('div', { 'style': 'padding:16px 16px 8px;font-size:14px;font-weight:600' }, _('Recent Alerts')),
				E('div', { 'style': 'overflow-x:auto' }, [
					E('table', { 'class': 'table', 'style': 'width:100%' }, rows)
				])
			]));
		} else {
			children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:32px;text-align:center;color:#6b7280;margin-bottom:20px' }, [
				E('div', { 'style': 'font-size:32px;margin-bottom:8px' }, '✅'),
				E('div', { 'style': 'font-size:16px;font-weight:500' }, _('No threats detected')),
				E('div', { 'style': 'font-size:13px;margin-top:4px' }, _('Your system is clean'))
			]));
		}

		// Log viewer
		var logLines = logOut.split('\n').filter(function(l) { return l.trim().length > 0; });
		var recentLog = logLines.slice(-30).reverse();

		children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px' }, [
			E('div', { 'style': 'font-size:14px;font-weight:600;margin-bottom:12px' }, _('ClamAV Log (last 30 lines)')),
			E('pre', { 'style': 'background:#f9fafb;border:1px solid #e5e7eb;border-radius:4px;padding:12px;font-size:11px;overflow-x:auto;max-height:300px;overflow-y:auto;margin:0;white-space:pre-wrap;word-break:break-all' },
				recentLog.join('\n') || _('No log entries'))
		]));

		dom.content(container, E('div', { 'style': 'max-width:900px' }, children));
	});
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	render: function() {
		var container = E('div');
		renderAlerts(container);

		poll.add(function() {
			return renderAlerts(container);
		}, 10);

		return container;
	}
});
