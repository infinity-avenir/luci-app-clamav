'use strict';
'require view';
'require dom';
'require poll';
'require fs';
'require ui';
'require uci';

function formatSize(bytes) {
	if (bytes < 1024) return bytes + ' B';
	if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
	return (bytes / 1048576).toFixed(1) + ' MB';
}

/* All 3 ClamAV databases */
var ALL_DATABASES = [
	{ file: 'main.cvd',     label: 'Main',     desc: 'Core signature database — hash-based malware signatures (MD5/SHA1/SHA256), PE section hashes, and known-bad file identifiers. ~170 MB, updated infrequently.', warnOOM: true },
	{ file: 'daily.cvd',    label: 'Daily',     desc: 'Daily updates — new malware hashes, logical signatures, extended signatures, phishing URLs, IOCs, and YARA-compatible rules. ~22 MB, updated multiple times daily.', warnOOM: false },
	{ file: 'bytecode.cvd', label: 'Bytecode',  desc: 'Bytecode signatures — heuristic detection rules that run in ClamAV\'s bytecode VM for behavioral analysis and advanced threat detection. ~275 KB.', warnOOM: false }
];

/* Parse CVD/CLD header: "ClamAV-VDB:buildtime:version:sigs:flevel:md5:sig:builder:stime" */
function parseCvdInfo(raw) {
	var dbs = {};
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
			dbs[fname] = {
				buildTime: fields[1] || '',
				version: parseInt(fields[2]) || 0,
				sigs: parseInt(fields[3]) || 0,
				flevel: parseInt(fields[4]) || 0,
				builder: fields.length >= 8 ? fields[7] : ''
			};
		}
	}
	return dbs;
}

/* Detect the database directory from clamd config, freshclam.conf, or default */
function getDbDir() {
	/* Try UCI first (clamd config) */
	var uciDir = uci.get('clamav', 'clamav', 'DatabaseDirectory');
	if (uciDir) return uciDir.replace(/\/+$/, '');

	/* Will also check freshclam.conf via shell in renderSignatures */
	return null;
}

/* Poll a status file until it appears (download complete) or timeout */
function pollForCompletion(tag, dbName, container, statusEl, btnResetFn) {
	var statusFile = '/tmp/clamav-dl-done-' + tag;
	var logFile = '/tmp/clamav-dl-log-' + tag;
	var maxPolls = 200; /* 200 × 3s = 10 minutes */
	var pollCount = 0;

	var timer = window.setInterval(function() {
		pollCount++;
		if (pollCount > maxPolls) {
			window.clearInterval(timer);
			statusEl.textContent = '';
			if (btnResetFn) btnResetFn();
			ui.addNotification(null, E('p', _('Download timed out. It may still be running in the background — check back shortly.')), 'warning');
			return;
		}

		fs.exec('/bin/sh', ['-c', 'cat ' + statusFile + ' 2>/dev/null']).then(function(res) {
			var rc = (res && res.stdout || '').trim();
			if (rc === '') return; /* Still in progress */

			window.clearInterval(timer);

			fs.exec('/bin/sh', ['-c',
				'cat ' + logFile + ' 2>/dev/null; rm -f ' + statusFile + ' ' + logFile
			]).then(function(logRes) {
				var output = (logRes && logRes.stdout) || '';
				var isRateLimited = output.indexOf('cool-down') !== -1 ||
					output.indexOf('429') !== -1 ||
					output.indexOf('Too Many') !== -1 ||
					output.indexOf('Forbidden') !== -1;

				statusEl.textContent = '';
				if (btnResetFn) btnResetFn();
				if (isRateLimited) {
					ui.addNotification(null, E('p', _('Rate limited by ClamAV CDN. Please wait 10-30 minutes and try again.')), 'danger');
				} else if (rc === '0') {
					ui.addNotification(null, E('p',
						dbName ? _('Successfully downloaded ') + dbName : _('Signature update completed successfully.')), 'info');
				} else {
					ui.addNotification(null, E('p',
						(dbName ? _('Download failed for ') + dbName + ': ' : _('Update failed: ')) +
						(output || _('Unknown error')).substring(0, 200)), 'danger');
				}
				renderSignatures(container);
			}).catch(function() {
				statusEl.textContent = '';
				if (btnResetFn) btnResetFn();
				renderSignatures(container);
			});
		}).catch(function() { /* poll error, ignore */ });
	}, 3000);
}

/* Download a single database by name using freshclam with a temp directory
 * to avoid "prune" conflicts when other .cvd files exist in the target dir.
 * Runs freshclam in the background to avoid XHR timeout on large downloads. */
function downloadDatabase(dbName, dbDir, container, statusEl) {
	statusEl.textContent = _('Preparing download...');

	var baseName = dbName.replace(/\.(cvd|cld)$/, '');
	var tmpDlDir = '/tmp/clamav-dl-' + baseName;
	var tmpConfPath = '/tmp/freshclam-dl-' + baseName + '.conf';
	var statusFile = '/tmp/clamav-dl-done-' + baseName;
	var logFile = '/tmp/clamav-dl-log-' + baseName;

	var tmpConf = [
		'DatabaseDirectory ' + tmpDlDir,
		'DatabaseOwner root',
		'DatabaseMirror database.clamav.net',
		'TestDatabases no',
		'Bytecode yes'
	].join('\n') + '\n';

	statusEl.textContent = _('Downloading ') + dbName + _(' (may take several minutes)...');

	/* Phase 1: Setup temp dir + config, launch freshclam in background */
	return fs.exec('/bin/sh', ['-c',
		'rm -rf ' + tmpDlDir + ' ' + statusFile + ' ' + logFile + ' && ' +
		'mkdir -p ' + tmpDlDir + ' && chmod 777 ' + tmpDlDir + ' && ' +
		"cat > " + tmpConfPath + " << 'TMPEOF'\n" + tmpConf + "TMPEOF\n" +
		'( freshclam --config-file=' + tmpConfPath + ' > ' + logFile + ' 2>&1; RC=$?; ' +
		'if [ $RC -eq 0 ] && [ -f ' + tmpDlDir + '/' + dbName + ' ]; then ' +
		'  mkdir -p ' + dbDir + ' && ' +
		'  cp ' + tmpDlDir + '/' + dbName + ' ' + dbDir + '/' + dbName + '; ' +
		'elif [ $RC -eq 0 ] && [ -f ' + tmpDlDir + '/' + baseName + '.cld ]; then ' +
		'  mkdir -p ' + dbDir + ' && ' +
		'  cp ' + tmpDlDir + '/' + baseName + '.cld ' + dbDir + '/' + baseName + '.cld; ' +
		'fi; ' +
		'echo $RC > ' + statusFile + '; ' +
		'rm -rf ' + tmpDlDir + ' ' + tmpConfPath + ' ) &'
	]).then(function() {
		/* Phase 2: Poll for completion */
		pollForCompletion(baseName, dbName, container, statusEl, null);
	}).catch(function(err) {
		statusEl.textContent = '';
		ui.addNotification(null, E('p', _('Failed to start download: ') + err.message), 'danger');
	});
}

function renderSignatures(container) {
	return uci.load('clamav').then(function() {
		/* Determine database directory */
		var dbDir = getDbDir();
		var dbDirPromise;

		if (dbDir) {
			dbDirPromise = Promise.resolve(dbDir);
		} else {
			/* Fall back: parse freshclam.conf for DatabaseDirectory */
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
		/* Read update frequency from UCI */
		var checksVal = uci.get('clamav', 'freshclam', 'Checks') || '1';
		var freqMap = { '12': _('Every 2 hours'), '6': _('Every 4 hours'), '3': _('Every 8 hours'), '2': _('Every 12 hours'), '1': _('Every 24 hours') };
		var updateFreqLabel = freqMap[checksVal] || checksVal + _(' checks/day');

		return Promise.all([
			fs.exec('/bin/sh', ['-c',
				'chmod 644 ' + dbDir + '/*.cvd ' + dbDir + '/*.cld 2>/dev/null; ' +
				'for f in ' + dbDir + '/*.cvd ' + dbDir + '/*.cld; do ' +
				'[ -f "$f" ] && echo "$(basename "$f")|$(dd if="$f" bs=512 count=1 2>/dev/null | tr -d "\\000")"; done'
			]).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/sh', ['-c', 'ls -la ' + dbDir + '/ 2>/dev/null']).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/sh', ['-c', 'clamdscan --version 2>/dev/null || clamd --version 2>/dev/null']).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/cat', ['/var/log/clamav/freshclam.log']).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/ps', ['w']).catch(function() { return { stdout: '' }; }),
			fs.exec('/bin/cat', ['/proc/swaps']).catch(function() { return { stdout: '' }; }),
			Promise.resolve(dbDir),
			Promise.resolve(updateFreqLabel)
		]);
	}).then(function(data) {
		var cvdRaw = (data[0] && data[0].stdout) || '';
		var lsOut = (data[1] && data[1].stdout) || '';
		var versionOut = (data[2] && data[2].stdout) || '';
		var freshLog = (data[3] && data[3].stdout) || '';
		var psOut = (data[4] && data[4].stdout) || '';
		var swapOut = (data[5] && data[5].stdout) || '';
		var dbDir = data[6];
		var updateFreqLabel = data[7];

		var installedDbs = parseCvdInfo(cvdRaw);

		/* File sizes from ls */
		var fileSizes = {};
		var lsLines = lsOut.split('\n');
		for (var i = 0; i < lsLines.length; i++) {
			var parts = lsLines[i].trim().split(/\s+/);
			if (parts.length >= 7) {
				var fname = parts[parts.length - 1];
				fileSizes[fname] = parseInt(parts[4]) || 0;
			}
		}

		var totalSigs = 0;
		var installedCount = 0;
		for (var key in installedDbs) {
			if (installedDbs.hasOwnProperty(key)) {
				totalSigs += installedDbs[key].sigs;
				installedCount++;
			}
		}

		var engineVersion = versionOut.trim() || '—';
		var freshclamRunning = psOut.indexOf('freshclam') !== -1;
		var swapActive = swapOut.indexOf('/') !== -1;

		/* Last update from freshclam log */
		var lastUpdate = '—';
		var updateLines = freshLog.split('\n');
		for (var k = updateLines.length - 1; k >= 0; k--) {
			if (updateLines[k].indexOf('updated') !== -1 || updateLines[k].indexOf('is up-to-date') !== -1) {
				lastUpdate = updateLines[k].substring(0, 50).trim();
				break;
			}
		}

		var children = [
			E('h2', { 'style': 'margin-bottom:16px' }, _('Signature Management'))
		];

		/* ── Summary cards ── */
		children.push(E('div', { 'style': 'display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px' }, [
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Total Signatures')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:#3b82f6' },
					totalSigs > 0 ? totalSigs.toLocaleString() : '—')
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Databases Installed')),
				E('div', { 'style': 'font-size:24px;font-weight:600;color:#8b5cf6' },
					installedCount + ' / ' + ALL_DATABASES.length)
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Auto-Update')),
				E('div', { 'style': 'font-size:20px;font-weight:600;color:#8b5cf6' }, updateFreqLabel)
			]),
			E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;text-align:center' }, [
				E('div', { 'style': 'font-size:13px;color:#6b7280;margin-bottom:4px' }, _('Swap')),
				E('div', { 'style': 'font-size:20px;font-weight:600;color:' + (swapActive ? '#22c55e' : '#f59e0b') },
					swapActive ? _('Active') : _('Off'))
			])
		]));

		/* ── Update All button ── */
		children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:20px' }, [
			E('div', { 'style': 'font-size:14px;font-weight:600;margin-bottom:12px' }, _('Update All Signatures')),
			E('div', { 'style': 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' }, [
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'click': function(ev) {
						var btn = ev.target;
						var statusSpan = btn.parentNode.querySelector('.update-status');
						btn.disabled = true;
						btn.textContent = _('Updating...');
						if (statusSpan) statusSpan.textContent = _(' (may take several minutes)');

						var tag = 'updateall';
						var statusFile = '/tmp/clamav-dl-done-' + tag;
						var logFile = '/tmp/clamav-dl-log-' + tag;

						fs.exec('/bin/sh', ['-c',
							'rm -f ' + statusFile + ' ' + logFile + ' && ' +
							'( chmod 777 "$(uci -q get clamav.freshclam.DatabaseDirectory || echo /usr/share/clamav)" 2>/dev/null; ' +
							'freshclam --config-file=/etc/clamav/freshclam.conf > ' + logFile + ' 2>&1; ' +
							'echo $? > ' + statusFile + ' ) &'
						]).then(function() {
							pollForCompletion(tag, null, container,
								statusSpan || E('span'),
								function() { btn.disabled = false; btn.textContent = _('Update All'); });
						}).catch(function(err) {
							btn.disabled = false;
							btn.textContent = _('Update All');
							ui.addNotification(null, E('p', _('Update failed: ') + err.message), 'danger');
						});
					}
				}, _('Update All')),
				E('span', { 'class': 'update-status', 'style': 'font-size:12px;color:#6b7280' }),
				E('span', { 'style': 'font-size:13px;color:#6b7280' },
					_('Last update: ') + lastUpdate)
			])
		]));

		/* ── Database table ── */
		var tableRows = [
			E('tr', { 'class': 'tr' }, [
				E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Database')),
				E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Status')),
				E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Signatures')),
				E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Version')),
				E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Size')),
				E('th', { 'class': 'th', 'style': 'font-weight:600;padding:8px 12px' }, _('Action'))
			])
		];

		for (var m = 0; m < ALL_DATABASES.length; m++) {
			var dbDef = ALL_DATABASES[m];
			var baseName = dbDef.file.replace(/\.cvd$/, '');
			var info = installedDbs[baseName + '.cvd'] || installedDbs[baseName + '.cld'] || null;
			var actualFile = installedDbs[baseName + '.cvd'] ? baseName + '.cvd' : (installedDbs[baseName + '.cld'] ? baseName + '.cld' : null);
			var isInstalled = !!info;
			var size = actualFile ? (fileSizes[actualFile] || 0) : 0;

			var statusBadge, sigCell, versionCell, sizeCell, actionCell;

			if (isInstalled) {
				statusBadge = E('span', { 'style': 'display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;background:#dcfce7;color:#166534' }, _('Installed'));
				sigCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px;font-weight:600;color:#3b82f6' },
					info.sigs > 0 ? info.sigs.toLocaleString() : '—');
				versionCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, 'v' + info.version);
				sizeCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, size > 0 ? formatSize(size) : '—');

				actionCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, [
					(function(dbFile, dir, cont) {
						var statusSpan = E('span', { 'style': 'font-size:12px;color:#6b7280;margin-left:6px' });
						return E('span', {}, [
							E('button', {
								'class': 'cbi-button cbi-button-action',
								'style': 'font-size:12px;padding:2px 10px',
								'click': function(ev) {
									ev.target.disabled = true;
									ev.target.textContent = _('Updating...');
									downloadDatabase(dbFile, dir, cont, statusSpan);
								}
							}, _('Update')),
							statusSpan
						]);
					})(dbDef.file, dbDir, container)
				]);
			} else {
				statusBadge = E('span', { 'style': 'display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;background:#fef2f2;color:#991b1b' }, _('Not Installed'));
				sigCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px;color:#9ca3af' }, '—');
				versionCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px;color:#9ca3af' }, '—');
				sizeCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px;color:#9ca3af' }, '—');

				actionCell = E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, [
					(function(dbFile, warnOOM, dir, cont) {
						var statusSpan = E('span', { 'style': 'font-size:12px;color:#6b7280;margin-left:6px' });
						return E('span', {}, [
							E('button', {
								'class': 'cbi-button cbi-button-apply',
								'style': 'font-size:12px;padding:2px 10px',
								'click': function(ev) {
									if (warnOOM) {
										if (!confirm(_('Warning: main.cvd is ~170 MB and may cause out-of-memory issues on routers with limited RAM. Continue?'))) {
											return;
										}
									}
									ev.target.disabled = true;
									ev.target.textContent = _('Downloading...');
									downloadDatabase(dbFile, dir, cont, statusSpan);
								}
							}, _('Download')),
							statusSpan
						]);
					})(dbDef.file, dbDef.warnOOM, dbDir, container)
				]);
			}

			tableRows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'style': 'padding:8px 12px;font-weight:500' }, [
					E('div', {}, dbDef.label + ' (' + dbDef.file + ')'),
					E('div', { 'style': 'font-size:11px;color:#9ca3af;margin-top:2px' }, dbDef.desc)
				]),
				E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, statusBadge),
				sigCell,
				versionCell,
				sizeCell,
				actionCell
			]));
		}

		/* Total row */
		tableRows.push(E('tr', { 'class': 'tr', 'style': 'background:#f9fafb;font-weight:600' }, [
			E('td', { 'class': 'td', 'style': 'padding:8px 12px' }, _('Total')),
			E('td', { 'class': 'td', 'style': 'padding:8px 12px' },
				installedCount + '/' + ALL_DATABASES.length + _(' installed')),
			E('td', { 'class': 'td', 'style': 'padding:8px 12px;color:#3b82f6' },
				totalSigs > 0 ? totalSigs.toLocaleString() : '—'),
			E('td', { 'class': 'td', 'colspan': '3' }, '')
		]));

		children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:20px' }, [
			E('div', { 'style': 'padding:16px 16px 8px;font-size:14px;font-weight:600' }, _('ClamAV Databases')),
			E('div', { 'style': 'padding:4px 16px 8px;font-size:12px;color:#6b7280' },
				_('Location: ') + dbDir),
			E('div', { 'style': 'overflow-x:auto' }, [
				E('table', { 'class': 'table', 'style': 'width:100%' }, tableRows)
			])
		]));

		/* ── Storage info ── */
		children.push(E('div', { 'style': 'background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:20px' }, [
			E('div', { 'style': 'font-size:14px;font-weight:600;margin-bottom:12px' }, _('Storage & Engine')),
			E('table', { 'class': 'table', 'style': 'width:100%' }, [
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'width:40%;color:#6b7280' }, _('Database Directory')),
					E('td', { 'class': 'td', 'style': 'font-family:monospace;font-size:13px' }, dbDir)
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Engine Version')),
					E('td', { 'class': 'td' }, engineVersion)
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Auto-Update Frequency')),
					E('td', { 'class': 'td', 'style': 'font-weight:600' }, updateFreqLabel)
				]),
				E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td', 'style': 'color:#6b7280' }, _('Swap Status')),
					E('td', { 'class': 'td' }, swapActive
						? E('span', { 'style': 'color:#22c55e;font-weight:600' }, _('Active'))
						: E('span', { 'style': 'color:#f59e0b' }, _('Not active — large databases may cause OOM')))
				])
			])
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
		renderSignatures(container);

		poll.add(function() {
			return renderSignatures(container);
		}, 15);

		return container;
	}
});
