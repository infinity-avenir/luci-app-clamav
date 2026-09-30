'use strict';
'require view';
'require dom';
'require poll';
'require fs';
'require ui';

function formatSize(bytes) {
	if (bytes < 1024) return bytes + ' B';
	if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
	return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDate(timestamp) {
	if (!timestamp) return '—';
	var d = new Date(parseInt(timestamp) * 1000);
	return d.toLocaleString();
}

function renderQuarantine(container) {
	return Promise.all([
		fs.exec('/bin/ls', ['-la', '--time-style=+%s', '/tmp/clamav-quarantine/']).catch(function() { return { stdout: '' }; }),
		fs.exec('/bin/cat', ['/var/log/clamav/clamd.log']).catch(function() { return { stdout: '' }; })
	]).then(function(data) {
		var lsOut = (data[0] && data[0].stdout) || '';
		var logOut = (data[1] && data[1].stdout) || '';

		// Parse quarantined files
		var files = [];
		var lsLines = lsOut.split('\n');
		for (var i = 0; i < lsLines.length; i++) {
			var line = lsLines[i].trim();
			if (!line || line.indexOf('total') === 0 || line.indexOf('d') === 0) continue;
			var parts = line.split(/\s+/);
			if (parts.length >= 7) {
				var fname = parts.slice(6).join(' ');
				if (fname === '.' || fname === '..') continue;
				files.push({
					name: fname,
					size: parseInt(parts[4]) || 0,
					mtime: parts[5] || '',
					permissions: parts[0]
				});
			}
		}

		// Build threat lookup from log
		var threatMap = {};
		var logLines = logOut.split('\n');
		for (var j = 0; j < logLines.length; j++) {
			var match = logLines[j].match(/^(.*?):\s+(.*?)\s+FOUND/);
			if (match) {
				var filename = match[1].split('/').pop();
				threatMap[filename] = match[2];
			}
		}

		// Total size
		var totalSize = 0;
		for (var k = 0; k < files.length; k++) {
			totalSize += files[k].size;
		}

		var children = [
			E('h2', { 'style': 'margin-bottom:16px' }, _('Quarantine'))
		];

		// Summary cards
		children.push(E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px' }, [
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Quarantined Files')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:#f59e0b' },
					String(files.length))
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Total Size')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:#6b7280' },
					formatSize(totalSize))
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Location')),
				E('div', { 'style': 'font-size:13px;font-weight:500;font-family:monospace;margin-top:6px' },
					'/tmp/clamav-quarantine')
			])
		]));

		// Actions
		if (files.length > 0) {
			children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:20px' }, [
				E('div', { 'style': 'font-size:14px;font-weight:600;margin-bottom:12px' }, _('Actions')),
				E('div', { 'style': 'display:flex;gap:8px;flex-wrap:wrap' }, [
					E('button', {
						'class': 'cbi-button cbi-button-reset',
						'click': function() {
							if (!confirm(_('Delete ALL quarantined files? This cannot be undone.')))
								return;
							fs.exec('/bin/sh', ['-c', 'rm -f /tmp/clamav-quarantine/*']).then(function() {
								ui.addNotification(null, E('p', _('All quarantined files have been deleted.')), 'info');
								renderQuarantine(container);
							});
						}
					}, _('Delete All')),
					E('button', {
						'class': 'cbi-button',
						'click': function() {
							renderQuarantine(container);
						}
					}, _('Refresh'))
				])
			]));
		}

		// File list
		if (files.length > 0) {
			var rows = [
				E('tr', { 'class': 'tr' }, [
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('File')),
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Threat')),
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Size')),
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Date')),
					E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Action'))
				])
			];

			for (var m = 0; m < files.length; m++) {
				(function(file) {
					var threat = threatMap[file.name] || _('Unknown');
					rows.push(E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td', 'style': 'padding:8px 12px;font-family:monospace;font-size:12px;word-break:break-all' }, file.name),
						E('td', { 'class': 'td', 'style': 'padding:8px 12px;color:#ef4444;font-weight:500' }, threat),
						E('td', { 'class': 'td', 'style': 'padding:8px 12px;white-space:nowrap' }, formatSize(file.size)),
						E('td', { 'class': 'td', 'style': 'padding:8px 12px;white-space:nowrap;color:#6b7280' }, formatDate(file.mtime)),
						E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, [
							E('button', {
								'class': 'cbi-button cbi-button-reset',
								'style': 'font-size:11px;padding:2px 8px',
								'click': function() {
									if (!confirm(_('Delete this file permanently?')))
										return;
									fs.exec('/bin/rm', ['-f', '/tmp/clamav-quarantine/' + file.name]).then(function() {
										renderQuarantine(container);
									});
								}
							}, _('Delete'))
						])
					]));
				})(files[m]);
			}

			children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden' }, [
				E('div', { 'style': 'padding:16px 16px 8px;font-size:14px;font-weight:600' }, _('Quarantined Files')),
				E('div', { 'style': 'overflow-x:auto' }, [
					E('table', { 'class': 'table', 'style': 'width:100%' }, rows)
				])
			]));
		} else {
			children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:32px;text-align:center;color:#6b7280' }, [
				E('div', { 'style': 'font-size:32px;margin-bottom:8px' }, '✅'),
				E('div', { 'style': 'font-size:16px;font-weight:500' }, _('Quarantine is empty')),
				E('div', { 'style': 'font-size:13px;margin-top:4px' }, _('No files are currently quarantined'))
			]));
		}

		dom.content(container, E('div', { 'style': 'max-width:900px' }, children));
	});
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	render: function() {
		var container = E('div');
		renderQuarantine(container);

		poll.add(function() {
			return renderQuarantine(container);
		}, 15);

		return container;
	}
});
