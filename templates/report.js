/* Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md. */
/* Posture report behaviour. Plain JS, no dependencies. The page is fully rendered without it; this adds view
   switching, the checks explorer filters, the check detail drawer, the executive toggle and CSV export. */
(function () {
  'use strict';
  var data = {};
  function readJson(id) { var el = document.getElementById(id); if (!el) { return null; } try { return JSON.parse(el.textContent); } catch (e) { return null; } }
  data.results = readJson('data-results') || [];
  data.catalog = readJson('data-catalog') || {};
  var byId = {}; data.results.forEach(function (r) { byId[r.id] = r; });

  // Views
  var views = Array.prototype.slice.call(document.querySelectorAll('section.view'));
  var links = Array.prototype.slice.call(document.querySelectorAll('nav.views a'));
  function show(id) {
    views.forEach(function (v) { v.classList.toggle('active', v.id === id); });
    links.forEach(function (a) { if (a.getAttribute('href') === '#' + id) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); } });
    window.scrollTo(0, 0);
  }
  function route() { var id = (location.hash || '#overview').substring(1); if (!document.getElementById(id)) { id = 'overview'; } show(id); }
  window.addEventListener('hashchange', route);
  route();

  // Executive toggle
  var exec = document.getElementById('toggle-exec');
  function setExec(on) {
    document.body.classList.toggle('executive', on);
    if (exec) { exec.setAttribute('aria-pressed', on ? 'true' : 'false'); }
    try { localStorage.setItem('tkp-exec', on ? '1' : '0'); } catch (e) { /* storage may be blocked */ }
  }
  if (exec) {
    exec.addEventListener('click', function () { setExec(!document.body.classList.contains('executive')); });
    var saved = null; try { saved = localStorage.getItem('tkp-exec'); } catch (e) { saved = null; }
    if (saved === '1' || (saved === null && document.body.getAttribute('data-template') === 'Executive')) { setExec(true); }
  }
  var printBtn = document.getElementById('print'); if (printBtn) { printBtn.addEventListener('click', function () { window.print(); }); }

  // Checks explorer
  var search = document.getElementById('filter-search'), fStatus = document.getElementById('filter-status'), fDomain = document.getElementById('filter-domain'), fSev = document.getElementById('filter-severity');
  var rows = Array.prototype.slice.call(document.querySelectorAll('#checks-table tbody tr'));
  function applyFilters() {
    var q = (search && search.value || '').toLowerCase(), st = fStatus && fStatus.value, dm = fDomain && fDomain.value, sv = fSev && fSev.value;
    var shown = 0;
    rows.forEach(function (tr) {
      var ok = (!st || tr.getAttribute('data-status') === st) && (!dm || tr.getAttribute('data-domain') === dm) && (!sv || tr.getAttribute('data-severity') === sv) && (!q || tr.textContent.toLowerCase().indexOf(q) >= 0);
      tr.style.display = ok ? '' : 'none'; if (ok) { shown++; }
    });
    var count = document.getElementById('checks-count'); if (count) { count.textContent = shown + ' of ' + rows.length; }
  }
  [search, fStatus, fDomain, fSev].forEach(function (el) { if (el) { el.addEventListener('input', applyFilters); el.addEventListener('change', applyFilters); } });
  applyFilters();

  // Drawer
  var drawer = document.getElementById('drawer');
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function openDrawer(id) {
    var r = byId[id], c = data.catalog[id] || {};
    if (!r || !drawer) { return; }
    var affected = (r.affected || []).map(function (a) { return '<li>' + esc(a.name) + (a.detail ? ' <span class="tech">(' + esc(a.detail) + ')</span>' : '') + '</li>'; }).join('');
    var exception = JSON.stringify({ check: r.id, object: (r.affected && r.affected[0] && r.affected[0].name) || null, justification: '', owner: '', approver: '', expires: '' }, null, 2);
    var fw = c.frameworks ? Object.keys(c.frameworks).filter(function (k) { return c.frameworks[k]; }).map(function (k) { return esc(k) + ' ' + esc(c.frameworks[k]); }).join(', ') : '';
    drawer.innerHTML = '<button class="close" type="button">Close</button>' +
      '<h2>' + esc(r.id) + ' ' + esc(r.title) + '</h2>' +
      '<p><span class="status ' + esc(r.status) + '">' + esc(r.status) + '</span> <span class="sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span> <span class="tech">domain ' + esc(r.domain) + '</span></p>' +
      (r.reason ? '<p>' + esc(r.reason) + '</p>' : '') +
      '<h4>Why it matters</h4><p>' + esc(c.narrative) + '</p>' +
      '<h4>Remediation</h4><p>' + esc(c.remediation) + (c.learn ? ' <a href="' + esc(c.learn) + '">Learn</a>' : '') + (c.deepLink ? ' <a href="' + esc(c.deepLink) + '">Open in portal</a>' : '') + '</p>' +
      ((c.license && c.license.length) ? '<p class="tech">Needs ' + esc(c.license.join(' or ')) + '</p>' : '') +
      (fw ? '<p class="tech">Frameworks: ' + fw + '</p>' : '') +
      (affected ? '<h4>Affected (' + r.affected.length + ')</h4><ul class="affected">' + affected + '</ul><button type="button" id="export-affected">Export CSV</button>' : '') +
      '<h4 class="tech">Evidence</h4><p class="tech">' + esc((r.evidence || []).join(', ')) + '</p>' +
      '<h4 class="tech">Thresholds</h4><pre class="tech">' + esc(JSON.stringify(r.thresholds || {}, null, 2)) + '</pre>' +
      '<h4 class="tech">Record an exception</h4><pre class="tech">' + esc(exception) + '</pre>';
    drawer.classList.add('open');
    drawer.querySelector('.close').addEventListener('click', closeDrawer);
    var ex = document.getElementById('export-affected');
    if (ex) { ex.addEventListener('click', function () { downloadCsv(r.id + '-affected.csv', ['name', 'detail'], (r.affected || []).map(function (a) { return [a.name, a.detail]; })); }); }
  }
  function closeDrawer() { if (drawer) { drawer.classList.remove('open'); } }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeDrawer(); } });
  Array.prototype.slice.call(document.querySelectorAll('tr[data-check], a[data-check]')).forEach(function (el) {
    el.classList.add('clickable');
    el.addEventListener('click', function (e) { e.preventDefault(); openDrawer(el.getAttribute('data-check')); });
    el.addEventListener('keydown', function (e) { if (e.key === 'Enter') { openDrawer(el.getAttribute('data-check')); } });
    el.setAttribute('tabindex', '0');
  });

  function downloadCsv(name, headers, rows) {
    var q = function (v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; };
    var text = [headers.map(q).join(',')].concat(rows.map(function (r) { return r.map(q).join(','); })).join('\r\n');
    var blob = new Blob([text], { type: 'text/csv' }), url = URL.createObjectURL(blob), a = document.createElement('a');
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
  }
  var exportAll = document.getElementById('export-checks');
  if (exportAll) { exportAll.addEventListener('click', function () { downloadCsv('checks.csv', ['id', 'domain', 'title', 'status', 'severity', 'affectedCount', 'reason'], data.results.map(function (r) { return [r.id, r.domain, r.title, r.status, r.severity, r.affectedCount, r.reason]; })); }); }
})();
