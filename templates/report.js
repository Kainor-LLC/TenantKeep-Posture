/* Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md. */
/* TenantKeep Posture report behaviour. Plain JS, no dependencies, no network. The page is fully rendered without
   it; this adds view switching, executive mode, filters, the check drawer and CSV exports. The page writes no
   files: exceptions and review dates are recorded with the module's cmdlets and read by the next run. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  function readJson(id) { var el = $(id); if (!el) { return null; } try { return JSON.parse(el.textContent); } catch (e) { return null; } }

  var data = {
    results: readJson('data-results') || [],
    catalog: readJson('data-catalog') || {},
    exceptions: readJson('data-exceptions') || [],
    attestations: readJson('data-attestations') || {},
    meta: readJson('data-meta') || {},
    labels: readJson('data-labels') || {}
  };
  var L = data.labels;
  L.status = L.status || {}; L.domains = L.domains || {}; L.frameworks = L.frameworks || {}; L.methods = L.methods || {}; L.thresholds = L.thresholds || {};
  var byId = {}; data.results.forEach(function (r) { byId[r.id] = r; });

  // ---------- labels ----------
  function words(s) { return String(s || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').replace(/^\s*\w/, function (c) { return c.toUpperCase(); }); }
  function statusLabel(s) { return L.status[s] || words(s); }
  function domainLabel(d) { return L.domains[d] || words(d); }
  function frameworkLabel(k) { return L.frameworks[k] || k; }
  function thresholdLabel(k) { return L.thresholds[k] || words(k); }
  function methodLabel(m) { var t = String(m || '').trim(); return L.methods[t] || L.methods[t.charAt(0).toLowerCase() + t.slice(1)] || words(t); }
  // Affected detail strings carry raw method and setting names from the evidence; render them as words.
  function humanDetail(text) {
    var s = String(text || '');
    s = s.replace(/registered:\s*([A-Za-z0-9;,\s]+)/g, function (m, list) { var parts = list.split(/[;,]\s*/).filter(Boolean).map(methodLabel); return 'registered: ' + (parts.length ? parts.join(', ') : 'nothing'); });
    s = s.replace(/\b(nothing)\b/g, 'nothing registered').replace(/nothing registered registered/g, 'nothing registered');
    return s;
  }
  function nameOf(a) { return a && typeof a === 'object' ? String(a.name || '') : String(a || ''); }

  // ---------- views ----------
  var views = Array.prototype.slice.call(document.querySelectorAll('section.view'));
  var links = Array.prototype.slice.call(document.querySelectorAll('nav.views a'));
  function show(id) {
    views.forEach(function (v) { v.classList.toggle('active', v.id === id); });
    links.forEach(function (a) { if (a.getAttribute('href') === '#' + id) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); } });
    window.scrollTo(0, 0);
  }
  function route() { var id = (location.hash || '#overview').substring(1); if (!$(id)) { id = 'overview'; } show(id); }
  window.addEventListener('hashchange', route);
  route();

  var exec = $('toggle-exec');
  function setExec(on) { document.body.classList.toggle('executive', on); if (exec) { exec.setAttribute('aria-pressed', on ? 'true' : 'false'); } try { localStorage.setItem('tkp-exec', on ? '1' : '0'); } catch (e) { /* storage may be blocked */ } }
  if (exec) {
    exec.addEventListener('click', function () { setExec(!document.body.classList.contains('executive')); });
    var saved = null; try { saved = localStorage.getItem('tkp-exec'); } catch (e) { saved = null; }
    if (saved === '1' || (saved === null && document.body.getAttribute('data-template') === 'Executive')) { setExec(true); }
  }
  var printBtn = $('print'); if (printBtn) { printBtn.addEventListener('click', function () { window.print(); }); }

  // ---------- toast ----------
  var toastEl = $('toast'); var toastTimer = null;
  function toast(msg) { if (!toastEl) { return; } toastEl.textContent = msg; toastEl.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 2600); }

  // ---------- checks explorer ----------
  var search = $('filter-search'), fStatus = $('filter-status'), fDomain = $('filter-domain'), fSev = $('filter-severity');
  var rows = Array.prototype.slice.call(document.querySelectorAll('#checks-table tbody tr'));
  function applyFilters() {
    var q = (search && search.value || '').toLowerCase(), st = fStatus && fStatus.value, dm = fDomain && fDomain.value, sv = fSev && fSev.value, shown = 0;
    rows.forEach(function (tr) {
      var ok = (!st || tr.getAttribute('data-status') === st) && (!dm || tr.getAttribute('data-domain') === dm) && (!sv || tr.getAttribute('data-severity') === sv) && (!q || tr.textContent.toLowerCase().indexOf(q) >= 0);
      tr.style.display = ok ? '' : 'none'; if (ok) { shown++; }
    });
    var count = $('checks-count'); if (count) { count.textContent = shown + ' of ' + rows.length; }
  }
  [search, fStatus, fDomain, fSev].forEach(function (el) { if (el) { el.addEventListener('input', applyFilters); el.addEventListener('change', applyFilters); } });
  applyFilters();

  // ---------- drawer ----------
  var drawer = $('drawer');
  function kvRows(obj, labelFn) { var keys = Object.keys(obj || {}); if (!keys.length) { return ''; } return '<dl class="kv">' + keys.map(function (k) { return '<dt>' + esc(labelFn(k)) + '</dt><dd>' + esc(typeof obj[k] === 'object' ? JSON.stringify(obj[k]) : obj[k]) + '</dd>'; }).join('') + '</dl>'; }
  function openDrawer(id) {
    var r = byId[id], c = data.catalog[id] || {}; if (!r || !drawer) { return; }
    var list = r.affected || [];
    var affected = list.map(function (a) { return '<li>' + esc(nameOf(a)) + (a && a.detail ? ' <span class="tech">(' + esc(humanDetail(a.detail)) + ')</span>' : '') + '</li>'; }).join('');
    var fw = c.frameworks ? Object.keys(c.frameworks).filter(function (k) { return c.frameworks[k]; }).map(function (k) { return '<span class="chip">' + esc(frameworkLabel(k)) + ' ' + esc(c.frameworks[k]) + '</span>'; }).join('') : '';
    var mine = data.exceptions.filter(function (e) { return e.check === id; });
    var exList = mine.map(function (e) { return '<li>' + (e.object ? '<strong>' + esc(e.object) + '</strong>: ' : '<strong>Whole check</strong>: ') + esc(e.justification || '') + ' <span class="tech">(owner ' + esc(e.owner || '') + ', approver ' + esc(e.approver || '') + ', until ' + esc(e.expires || 'no expiry') + ')</span></li>'; }).join('');
    drawer.innerHTML = '<button class="close" type="button">Close</button>' +
      '<h2>' + esc(r.id) + ' ' + esc(r.title) + '</h2>' +
      '<p><span class="status ' + esc(r.status) + '">' + esc(statusLabel(r.status)) + '</span> <span class="sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span> <span class="chip">' + esc(domainLabel(r.domain)) + '</span>' + ((c.license && c.license.length) ? '<span class="chip">Needs ' + esc(c.license.join(' or ')) + '</span>' : '') + '</p>' +
      (r.reason ? '<p>' + esc(r.reason) + '</p>' : '') +
      '<h4>Why It Matters</h4><p>' + esc(c.narrative) + '</p>' +
      '<h4>Remediation</h4><p>' + esc(c.remediation) + '</p><p>' + (c.learn ? '<a class="btn" href="' + esc(c.learn) + '" target="_blank" rel="noopener">Microsoft Learn</a> ' : '') + (c.deepLink ? '<a class="btn" href="' + esc(c.deepLink) + '" target="_blank" rel="noopener">Open in Portal</a>' : '') + '</p>' +
      (fw ? '<h4>Frameworks</h4><p class="chips">' + fw + '</p>' : '') +
      (affected ? '<h4>Affected (' + list.length + ')</h4><ul class="affected">' + affected + '</ul><p><button type="button" id="export-affected">Export Affected CSV</button></p>' : '') +
      (exList ? '<h4>Accepted Risks</h4><ul class="exception-list">' + exList + '</ul>' : '') +
      inputPanel(c) +
      (r.evidence && r.evidence.length ? '<h4 class="tech">Evidence</h4><p class="chips tech">' + r.evidence.map(function (f) { return '<span class="chip">' + esc(f) + '</span>'; }).join('') + '</p>' : '') +
      (r.thresholds && Object.keys(r.thresholds).length ? '<h4 class="tech">Thresholds Used</h4>' + kvRows(r.thresholds, thresholdLabel) : '');
    drawer.classList.add('open');
    drawer.querySelector('.close').addEventListener('click', closeDrawer);
    var ex = $('export-affected'); if (ex) { ex.addEventListener('click', function () { downloadText(r.id + '-affected.csv', toCsv(['Name', 'Detail'], list.map(function (a) { return [nameOf(a), humanDetail(a && a.detail)]; })), 'text/csv'); }); }
  }
  // Checks no API can answer ask for a review date or for report files; both live in the client folder.
  function inputPanel(c) {
    var inp = c.input; if (!inp) { return ''; }
    var portal = inp.portal ? ' <a class="btn" href="' + esc(inp.portal) + '" target="_blank" rel="noopener">Open the portal</a>' : '';
    if (inp.kind === 'attestation') {
      var current = data.attestations[inp.key];
      return '<h4>What To Provide</h4><p>' + esc(inp.steps) + '</p><p>' + portal + '</p><p class="hint">' + esc(inp.label) + ': ' + esc(current ? String(current).substring(0, 10) : 'not recorded') + '.</p>';
    }
    if (inp.kind === 'files') {
      return '<h4>What To Provide</h4><p>' + esc(inp.steps) + '</p><p>' + portal + '</p><p class="hint">Copy the files into ' + esc(inp.folder) + ' in the client folder; the next run reads the newest one.</p>';
    }
    return '';
  }
  function closeDrawer() { if (drawer) { drawer.classList.remove('open'); } }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeDrawer(); } });
  function bindCheckLinks(root) {
    Array.prototype.slice.call((root || document).querySelectorAll('tr[data-check], a[data-check]')).forEach(function (el) {
      if (el.getAttribute('data-bound')) { return; } el.setAttribute('data-bound', '1');
      el.classList.add('clickable');
      el.addEventListener('click', function (e) { if (e.target && e.target.tagName === 'BUTTON') { return; } e.preventDefault(); openDrawer(el.getAttribute('data-check')); });
      el.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target === el) { openDrawer(el.getAttribute('data-check')); } });
      el.setAttribute('tabindex', '0');
    });
  }
  bindCheckLinks(document);

  // ---------- exports ----------
  function toCsv(headers, list) { var q = function (v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }; return [headers.map(q).join(',')].concat(list.map(function (r) { return r.map(q).join(','); })).join('\r\n') + '\r\n'; }
  function downloadText(name, text, type) { var blob = new Blob([text], { type: type || 'application/json' }), url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); toast('Downloaded ' + name); }
  var exportAll = $('export-checks');
  if (exportAll) { exportAll.addEventListener('click', function () { downloadText('checks.csv', toCsv(['ID', 'Domain', 'Title', 'Status', 'Severity', 'Affected', 'Reason'], data.results.map(function (r) { return [r.id, domainLabel(r.domain), r.title, statusLabel(r.status), r.severity, (r.affected || []).length, r.reason]; })), 'text/csv'); }); }

  // Humanise the server-rendered detail cells once.
  Array.prototype.slice.call(document.querySelectorAll('[data-human]')).forEach(function (el) { el.textContent = humanDetail(el.textContent); });
})();
