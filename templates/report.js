/* Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md. */
/* TenantKeep Posture report behaviour. Plain JS, no dependencies, no network. The page is fully rendered without
   it; this adds view switching, executive mode, filters, the check drawer and CSV exports. The page writes no
   files: accepting a risk or recording a review copies a module command (Add-PostureException,
   Remove-PostureException, Set-PostureAttestation) that writes the client folder and rebuilds this report. */
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

  // ---------- commands to copy ----------
  // PowerShell single quotes, including the typographic ones PowerShell also treats as quotes.
  function psq(v) { return "'" + String(v).replace(/['\u2018\u2019\u201A\u201B]/g, function (q) { return q + q; }) + "'"; }
  function target() { return data.meta.tenantId ? '-TenantId ' + psq(data.meta.tenantId) : '-Client ' + psq(data.meta.clientFolder || ''); }
  function cmdBlock(id, text) { return '<div class="cmd"><code id="' + id + '">' + esc(text) + '</code><button type="button" data-copy="' + id + '">Copy</button></div>'; }
  function copyText(text) {
    var done = function () { toast('Copied. Paste it into PowerShell.'); };
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text) ? done() : toast('Select the command and copy it.'); }); return; }
    if (fallbackCopy(text)) { done(); } else { toast('Select the command and copy it.'); }
  }
  function fallbackCopy(text) { var t = document.createElement('textarea'); t.value = text; t.setAttribute('readonly', ''); t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); var ok = false; try { ok = document.execCommand('copy'); } catch (e) { ok = false; } document.body.removeChild(t); return ok; }
  function bindCopy(root) { Array.prototype.slice.call(root.querySelectorAll('[data-copy]')).forEach(function (b) { b.addEventListener('click', function () { var el = $(b.getAttribute('data-copy')); if (el) { copyText(el.textContent); } }); }); }
  var RERUN_HINT = 'Paste it into PowerShell. It rebuilds this report from the same evidence in a few seconds, with no sign-in; then refresh the page.';

  // ---------- views ----------
  var views = Array.prototype.slice.call(document.querySelectorAll('section.view'));
  var links = Array.prototype.slice.call(document.querySelectorAll('nav.views a'));
  function show(id) {
    views.forEach(function (v) { v.classList.toggle('active', v.id === id); });
    links.forEach(function (a) { if (a.getAttribute('href') === '#' + id) { a.setAttribute('aria-current', 'page'); } else { a.removeAttribute('aria-current'); } });
    window.scrollTo(0, 0);
  }
  // A view id shows that view; any other element id (a finding card, a tactic) shows the view holding it, then scrolls to it.
  function route() {
    var el = $((location.hash || '#overview').substring(1)), view = el && el.closest ? el.closest('section.view') : null;
    if (!view) { show('overview'); return; }
    show(view.id);
    if (view !== el) { el.scrollIntoView(); }
  }
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
  // Licensing: recompute the options when goals or vendor toggles change (templates/licensing.js); nothing is saved.
  var licData = $('data-licensing') ? JSON.parse($('data-licensing').textContent) : null;
  var live = $('advice-live');
  function adviceState() {
    var goals = Array.prototype.slice.call(document.querySelectorAll('.adv-goal:checked')).map(function (c) { return c.value; });
    var tp = {}; Object.keys(licData.thirdParty || {}).forEach(function (k) { tp[k] = licData.thirdParty[k]; });
    Array.prototype.slice.call(document.querySelectorAll('.adv-cat')).forEach(function (c) {
      var name = document.querySelector('.adv-name[data-cat="' + c.value + '"]');
      tp[c.value] = c.checked ? ((name && name.value.trim()) || 'another product') : 'none';
    });
    return { goals: goals, thirdParty: tp, seats: licData.seats };
  }
  function renderAdvice() {
    if (!licData || !live || typeof tkLicenseAdvice !== 'function') { return; }
    var a = tkLicenseAdvice(licData, adviceState());
    var goalName = {}; licData.goals.forEach(function (g) { goalName[g.id] = g.name; });
    var forEl = $('advice-for'); if (forEl) { forEl.textContent = 'For ' + (adviceState().goals.length ? 'the goals ticked below' : 'the core goals') + ': ' + a.goals.map(function (id) { return goalName[id]; }).join('; ') + '.'; }
    if (a.met) { live.innerHTML = '<p class="banner ready"><strong>Covered.</strong> The licences you hold, with the products you named, include every feature these goals need. The work is configuration: see Recommendations.</p>'; return; }
    var cards = a.options.map(function (o) {
      return '<div class="advice-card"><h4>' + esc(o.title) + '</h4><ul class="advice-skus">' + o.skus.map(function (s) { return '<li><strong>' + esc(s.name) + '</strong> <code class="tech">' + esc(s.sku) + '</code>' + (s.verify ? ' <span class="tech">(verify: ' + esc(s.verify) + ')</span>' : '') + '</li>'; }).join('') + '</ul>' +
        (o.adds.length ? '<p><strong>Adds</strong> ' + esc(o.adds.join(', ')) + '.</p>' : '') +
        (o.redundant.length ? '<p class="muted"><strong>Already covered</strong> ' + esc(o.redundant.map(function (r) { return r.name + ' (' + r.vendor + ')'; }).join(', ')) + '.</p>' : '') +
        (o.alsoIncludes.length ? '<p class="muted"><strong>Also includes</strong> ' + esc(o.alsoIncludes.join(', ')) + '.</p>' : '') + '</div>';
    }).join('');
    live.innerHTML = '<p>Missing: ' + esc(a.missing.map(function (g) { return g.join(' or '); }).join('; ')) + '.</p><div class="advice-options">' + cards + '</div><p class="hint">For ' + licData.seats + ' licensed users. Compare these with your Microsoft partner; prices and eligibility are theirs to quote.</p>';
  }
  Array.prototype.slice.call(document.querySelectorAll('.adv-goal, .adv-cat, .adv-name')).forEach(function (el) { el.addEventListener(el.type === 'text' ? 'input' : 'change', renderAdvice); });
  // Licensing: show only the goals not covered.
  var unmetOnly = $('goals-unmet-only');
  if (unmetOnly) { unmetOnly.addEventListener('change', function () { var g = document.querySelector('.goal-cards'); if (g) { g.classList.toggle('unmet-only', unmetOnly.checked); } }); }
  // A chart's View the checks link, or a domain tile: open the explorer filtered to that domain.
  Array.prototype.slice.call(document.querySelectorAll('[data-filter-domain]')).forEach(function (a) {
    a.addEventListener('click', function () { if (fDomain) { fDomain.value = a.getAttribute('data-filter-domain'); } if (fStatus) { fStatus.value = ''; } applyFilters(); });
  });
  applyFilters();

  // ---------- drawer ----------
  var drawer = $('drawer');
  function kvRows(obj, labelFn, valueFn) { var keys = Object.keys(obj || {}); if (!keys.length) { return ''; } return '<dl class="kv">' + keys.map(function (k) { var v = obj[k]; return '<dt>' + esc(labelFn(k)) + '</dt><dd>' + esc(valueFn ? valueFn(v) : (typeof v === 'object' ? JSON.stringify(v) : v)) + '</dd>'; }).join('') + '</dl>'; }
  // A fact name as words (anonymousLinkDays: Anonymous link days), the same rule the report's cards use.
  var ACRONYMS = /\b(mfa|ca|spo|dlp|pim|sspr|tap|dkim|dmarc|spf|mde|edr|av|os|ip|id|url|api|smtp|imap|pop|ews|tls|ssl)\b/gi;
  function factLabel(k) { if (L.facts && L.facts[k]) { return L.facts[k]; } var t = words(String(k).replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')); t = t.charAt(0) + t.slice(1).toLowerCase(); return t.replace(ACRONYMS, function (m) { return m.toUpperCase(); }).replace(/\bpct\b/i, '(%)'); }
  function factValue(v) { if (v === true) { return 'yes'; } if (v === false) { return 'no'; } if (v === null || v === undefined || v === '') { return 'none'; } return typeof v === 'number' ? v.toLocaleString() : String(v); }
  function openDrawer(id) {
    var r = byId[id], c = data.catalog[id] || {}; if (!r || !drawer) { return; }
    var list = r.affected || [];
    var affected = list.map(function (a) { return '<li>' + esc(nameOf(a)) + (a && a.detail ? ' <span class="tech">(' + esc(humanDetail(a.detail)) + ')</span>' : '') + '</li>'; }).join('');
    var fw = c.frameworks ? Object.keys(c.frameworks).filter(function (k) { return c.frameworks[k]; }).map(function (k) { return '<span class="chip">' + esc(frameworkLabel(k)) + ' ' + esc(c.frameworks[k]) + '</span>'; }).join('') : '';
    var atk = (c.attack || []).map(function (t) { return '<li><a href="' + esc(t.url) + '" target="_blank" rel="noopener"><code>' + esc(t.id) + '</code> ' + esc(t.name) + '</a>' + (t.tactics && t.tactics.length ? ' <span class="tech">(' + esc(t.tactics.join(', ')) + ')</span>' : '') + '</li>'; }).join('');
    var mine = data.exceptions.filter(function (e) { return e.check === id; });
    var exList = mine.map(function (e, i) { return '<li>' + (e.object ? '<strong>' + esc(e.object) + '</strong>: ' : '<strong>Whole check</strong>: ') + esc(e.justification || '') + ' <span class="tech">(owner ' + esc(e.owner || '') + ', approver ' + esc(e.approver || '') + ', until ' + esc(e.expires || 'no expiry') + ')</span>' + cmdBlock('cmd-remove-' + i, 'Remove-PostureException ' + target() + ' -Check ' + psq(id) + (e.object ? ' -Object ' + psq(e.object) : '')) + '</li>'; }).join('');
    drawer.innerHTML = '<button class="close" type="button">Close</button>' +
      '<h2>' + esc(r.id) + ' ' + esc(r.title) + '</h2>' +
      '<p><span class="status ' + esc(r.status) + '">' + esc(statusLabel(r.status)) + '</span> <span class="sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span> <span class="chip">' + esc(domainLabel(r.domain)) + '</span>' + ((c.license && c.license.length) ? '<span class="chip">Needs ' + esc(c.license.join(' or ')) + '</span>' : '') + '</p>' +
      (r.reason ? '<p>' + esc(r.reason) + '</p>' : '') +
      (r.observed && Object.keys(r.observed).length ? '<h4>What We Found</h4>' + kvRows(r.observed, factLabel, factValue) : '') +
      '<h4>Why It Matters</h4><p>' + esc(c.narrative) + '</p>' +
      (c.userImpact ? '<h4>What Users Notice</h4><p><span class="chip ui-' + esc(c.userImpact.level) + '">User impact: ' + esc(c.userImpact.level) + '</span> ' + esc(c.userImpact.text) + '</p>' : '') +
      '<h4>Remediation</h4>' + (c.steps && c.steps.length > 1 ? '<ol class="steps">' + c.steps.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ol>' : '<p>' + esc(c.remediation) + '</p>') + '<p>' + (c.learn ? '<a class="btn" href="' + esc(c.learn) + '" target="_blank" rel="noopener">Microsoft Learn</a> ' : '') + (c.deepLink ? '<a class="btn" href="' + esc(c.deepLink) + '" target="_blank" rel="noopener">Open in Portal</a>' : '') + '</p>' +
      (fw ? '<h4>Frameworks</h4><p class="chips">' + fw + '</p>' : '') +
      (atk ? '<h4>MITRE ATT&amp;CK</h4><ul class="attack-list">' + atk + '</ul>' : '') +
      (affected ? '<h4>Affected (' + Math.max(list.length, r.affectedCount || 0).toLocaleString() + ')</h4>' + ((r.affectedCount || 0) > list.length ? '<p class="hint">Showing the first ' + list.length + '. ' + (r.affectedListed != null && r.affectedListed < r.affectedCount ? 'The run lists ' + r.affectedListed.toLocaleString() + ' at most for this check; those are in affected/' + esc(r.id) + '.csv in the run folder.' : 'Every one is in affected/' + esc(r.id) + '.csv in the run folder.') + '</p>' : '') + '<ul class="affected">' + affected + '</ul><p><button type="button" id="export-affected">Export Affected CSV</button></p>' : '') +
      (exList ? '<h4>Accepted Risks</h4><p class="hint">To withdraw one, copy its command. ' + esc(RERUN_HINT) + '</p><ul class="exception-list">' + exList + '</ul>' : '') +
      acceptPanel(r, list) +
      inputPanel(c) +
      (r.evidence && r.evidence.length ? '<h4 class="tech">Evidence</h4><p class="chips tech">' + r.evidence.map(function (f) { return '<span class="chip">' + esc(f) + '</span>'; }).join('') + '</p>' : '') +
      (r.thresholds && Object.keys(r.thresholds).length ? '<h4 class="tech">Thresholds Used</h4>' + kvRows(r.thresholds, thresholdLabel) : '');
    drawer.classList.add('open');
    drawer.querySelector('.close').addEventListener('click', closeDrawer);
    var ex = $('export-affected'); if (ex) { ex.addEventListener('click', function () { downloadText(r.id + '-affected.csv', toCsv(['Name', 'Detail'], list.map(function (a) { return [nameOf(a), humanDetail(a && a.detail)]; })), 'text/csv'); }); }
    var scope = $('accept-scope'), acceptCmd = $('cmd-accept');
    if (scope && acceptCmd) { scope.addEventListener('change', function () { acceptCmd.textContent = acceptCommand(r.id, scope.value); }); }
    bindCopy(drawer);
  }
  function acceptCommand(id, object) { return 'Add-PostureException ' + target() + ' -Check ' + psq(id) + (object ? ' -Object ' + psq(object) : ''); }
  // Accepting a risk is a decision recorded outside the page: the command asks for the reason, owner and expiry.
  function acceptPanel(r, list) {
    if (r.status !== 'fail') { return ''; }
    var names = list.map(nameOf).filter(Boolean);
    var picker = names.length ? '<label class="scope">Accept for<select id="accept-scope"><option value="">The whole check</option>' + names.map(function (n) { return '<option value="' + esc(n) + '">' + esc(n) + '</option>'; }).join('') + '</select></label>' : '';
    return '<h4>Accept This Risk</h4><p class="hint">When this is a decision rather than a gap, copy the command. It asks for the reason, the owner and an expiry, and the check counts as accepted until then. ' + esc(RERUN_HINT) + '</p>' + picker + cmdBlock('cmd-accept', acceptCommand(r.id, ''));
  }
  // Checks no API can answer ask for a review date or for report files; both live in the client folder.
  function inputPanel(c) {
    var inp = c.input; if (!inp) { return ''; }
    var portal = inp.portal ? ' <a class="btn" href="' + esc(inp.portal) + '" target="_blank" rel="noopener">Open the portal</a>' : '';
    if (inp.kind === 'attestation') {
      var current = data.attestations[inp.key];
      return '<h4>What To Provide</h4><p>' + esc(inp.steps) + '</p><p>' + portal + '</p><p class="hint">' + esc(inp.label) + ': ' + esc(current ? String(current).substring(0, 10) : 'not recorded') + '. After the review, copy the command to record today\'s date. ' + esc(RERUN_HINT) + '</p>' + cmdBlock('cmd-attest', 'Set-PostureAttestation ' + target() + ' -Key ' + psq(inp.key));
    }
    if (inp.kind === 'files') {
      if (inp.command) { return '<h4>What To Provide</h4><p>' + esc(inp.steps) + '</p><p>' + portal + '</p>' + cmdBlock('cmd-import', inp.command + ' ' + target() + ' -Path ') + '<p class="hint">' + esc(RERUN_HINT) + '</p>'; }
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
  function toCsv(headers, list) { var q = function (v) { var s = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; } return '"' + s.replace(/"/g, '""') + '"'; }; return [headers.map(q).join(',')].concat(list.map(function (r) { return r.map(q).join(','); })).join('\r\n') + '\r\n'; }
  function downloadText(name, text, type) { var blob = new Blob([text], { type: type || 'application/json' }), url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); toast('Downloaded ' + name); }
  var exportAll = $('export-checks');
  if (exportAll) { exportAll.addEventListener('click', function () { downloadText('checks.csv', toCsv(['ID', 'Domain', 'Title', 'Status', 'Severity', 'Affected', 'Reason'], data.results.map(function (r) { return [r.id, domainLabel(r.domain), r.title, statusLabel(r.status), r.severity, (r.affectedCount != null ? r.affectedCount : (r.affected || []).length), r.reason]; })), 'text/csv'); }); }

  bindCopy(document);

  // Domains: the charts of each domain are folded sections. The button opens or folds them all; printing opens them
  // for the paper and puts them back; ?areas=open opens them from the address, for a screenshot or a link.
  var areasToggle = $('areas-toggle');
  function areaList() { return Array.prototype.slice.call(document.querySelectorAll('details.area')); }
  function setAreas(open) {
    areaList().forEach(function (d) { d.open = open; });
    if (areasToggle) { areasToggle.textContent = open ? 'Fold all' : 'Open all'; areasToggle.setAttribute('aria-expanded', open ? 'true' : 'false'); }
  }
  if (areasToggle) { areasToggle.addEventListener('click', function () { setAreas(!areaList().every(function (d) { return d.open; })); }); }
  if (/[?&]areas=open(&|$)/.test(window.location.search)) { setAreas(true); }
  var areasBeforePrint = null;
  window.addEventListener('beforeprint', function () { areasBeforePrint = areaList().map(function (d) { return d.open; }); areaList().forEach(function (d) { d.open = true; }); });
  window.addEventListener('afterprint', function () { if (areasBeforePrint) { areaList().forEach(function (d, i) { d.open = areasBeforePrint[i]; }); areasBeforePrint = null; } });

  // Humanise the server-rendered detail cells once.
  Array.prototype.slice.call(document.querySelectorAll('[data-human]')).forEach(function (el) { el.textContent = humanDetail(el.textContent); });
})();
