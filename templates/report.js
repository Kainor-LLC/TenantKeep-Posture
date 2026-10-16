/* Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md. */
/* Tenantkeep Posture report behaviour. Plain JS, no dependencies, no network. The page is fully rendered without
   it; this adds view switching, filters, the check drawer with the exception form, the live re-score, the risk
   register, the settings view, and saving into the client folder through the browser's folder picker (Chromium),
   with file downloads as the fallback everywhere else. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  function readJson(id) { var el = $(id); if (!el) { return null; } try { return JSON.parse(el.textContent); } catch (e) { return null; } }

  var data = {
    results: readJson('data-results') || [],
    catalog: readJson('data-catalog') || {},
    exceptions: readJson('data-exceptions') || [],
    profile: readJson('data-profile') || {},
    register: readJson('data-register') || [],
    meta: readJson('data-meta') || {},
    labels: readJson('data-labels') || {}
  };
  var L = data.labels;
  L.status = L.status || {}; L.domains = L.domains || {}; L.frameworks = L.frameworks || {}; L.methods = L.methods || {}; L.thresholds = L.thresholds || {};
  var WEIGHT = { Critical: 4, High: 3, Medium: 2, Low: 1 };
  var byId = {}; data.results.forEach(function (r) { byId[r.id] = r; });
  var state = {
    exceptions: data.exceptions.slice(),            // the working list; starts as what the report was built with
    removed: [],                                    // exceptions removed in this session (so a save removes them from the file too)
    register: {},                                   // id -> { owner, status, effort, dependency, notes } edits
    profile: JSON.parse(JSON.stringify(data.profile || {})),
    dirty: { exceptions: false, register: false, profile: false },
    folder: null
  };
  data.register.forEach(function (row) { if (row && row.ID) { state.register[row.ID] = { owner: row.Owner || '', status: row.Status || '', effort: row['Effort S/M/L/XL'] || '', dependency: row.Dependency || '', notes: row.Notes || '' }; } });

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

  // ---------- live evaluation of exceptions ----------
  function nameOf(a) { return a && typeof a === 'object' ? String(a.name || '') : String(a || ''); }
  function activeExceptions() { var now = new Date(); return state.exceptions.filter(function (e) { return e && e.check && !(e.expires && new Date(e.expires) < now); }); }
  // Returns the effective status and affected list for a result, applying the working exception list the same way the engine does.
  function effective(r) {
    var base = { status: r.status, affected: (r.affected || []).slice(), reason: r.reason || '' };
    if (r.status !== 'fail' && r.status !== 'acceptedRisk') { return base; }
    var original = r.originalAffected || r.affected || [];
    var mine = activeExceptions().filter(function (e) { return e.check === r.id; });
    var checkLevel = mine.filter(function (e) { return !e.object; }), objectLevel = mine.filter(function (e) { return e.object; });
    if (checkLevel.length) { return { status: 'acceptedRisk', affected: [], reason: 'Accepted risk: ' + (checkLevel[0].justification || '') + ' (owner ' + (checkLevel[0].owner || '') + ', until ' + (checkLevel[0].expires || 'no expiry') + ').' }; }
    if (original.length) {
      var names = objectLevel.map(function (e) { return e.object; });
      var remaining = original.filter(function (a) { return names.indexOf(nameOf(a)) < 0; });
      if (remaining.length === 0 && objectLevel.length) { return { status: 'acceptedRisk', affected: [], reason: 'Accepted risk for every affected object.' }; }
      if (remaining.length < original.length) { return { status: 'fail', affected: remaining, reason: (original.length - remaining.length) + ' object(s) accepted by exception; ' + remaining.length + ' remain.' }; }
      return { status: 'fail', affected: remaining, reason: base.reason };
    }
    if (!mine.length && r.status === 'acceptedRisk') { return { status: 'fail', affected: original.slice(), reason: 'Exception removed in this session.' }; }
    return base;
  }
  data.results.forEach(function (r) { r.originalAffected = (r.affectedBeforeExceptions || r.affected || []).slice(); });
  function score(list) {
    var earned = 0, possible = 0;
    list.forEach(function (r) { var ef = effective(r); if (['pass', 'fail', 'acceptedRisk'].indexOf(ef.status) < 0) { return; } var w = WEIGHT[r.severity] || 1; possible += w; if (ef.status !== 'fail') { earned += w; } });
    return possible ? Math.round(100 * earned / possible) : null;
  }
  function grade(s) { return s == null ? 'n/a' : s >= 90 ? 'A' : s >= 80 ? 'B' : s >= 70 ? 'C' : s >= 60 ? 'D' : 'F'; }
  function recompute() {
    var s = score(data.results), counts = {};
    data.results.forEach(function (r) { var st = effective(r).status; counts[st] = (counts[st] || 0) + 1; });
    var g = $('score-grade'), v = $('score-value'); if (g) { g.textContent = grade(s); } if (v) { v.textContent = 'Posture score ' + (s == null ? 'not collected yet' : s); }
    Object.keys(counts).concat(['pass', 'fail', 'acceptedRisk', 'coveredBy', 'notEvaluated', 'notApplicable']).forEach(function (k) { var el = $('count-' + k); if (el) { el.textContent = counts[k] || 0; } });
    Array.prototype.slice.call(document.querySelectorAll('[data-domain-score]')).forEach(function (el) {
      var d = el.getAttribute('data-domain-score'); var ds = score(data.results.filter(function (r) { return r.domain === d; }));
      el.textContent = ds == null ? 'not collected yet' : ds; var bar = el.parentNode.parentNode.querySelector('.bar i'); if (bar) { bar.style.width = (ds || 0) + '%'; }
    });
    Array.prototype.slice.call(document.querySelectorAll('tr[data-check]')).forEach(function (tr) {
      var r = byId[tr.getAttribute('data-check')]; if (!r) { return; } var ef = effective(r);
      var cell = tr.querySelector('.status'); if (cell) { cell.className = 'status ' + ef.status; cell.textContent = statusLabel(ef.status); }
      tr.setAttribute('data-status', ef.status);
      var aff = tr.querySelector('[data-affected-count]'); if (aff) { aff.textContent = ef.affected.length; }
    });
    var live = $('score-live'); var pending = state.exceptions.length - data.exceptions.length + state.removed.length;
    if (live) { live.textContent = (state.dirty.exceptions) ? 'Includes ' + Math.abs(pending) + ' exception change(s) not yet saved; the next run makes them permanent.' : ''; }
    renderRegister();
    updateSaveBar();
  }

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
    var ef = effective(r);
    var affected = ef.affected.map(function (a) { return '<li>' + esc(nameOf(a)) + (a && a.detail ? ' <span class="tech">(' + esc(humanDetail(a.detail)) + ')</span>' : '') + '</li>'; }).join('');
    var fw = c.frameworks ? Object.keys(c.frameworks).filter(function (k) { return c.frameworks[k]; }).map(function (k) { return '<span class="chip">' + esc(frameworkLabel(k)) + ' ' + esc(c.frameworks[k]) + '</span>'; }).join('') : '';
    var mine = state.exceptions.filter(function (e) { return e.check === id; });
    var exList = mine.map(function (e, i) { return '<li>' + (e.object ? '<strong>' + esc(e.object) + '</strong>: ' : '<strong>Whole check</strong>: ') + esc(e.justification || '') + ' <span class="tech">(owner ' + esc(e.owner || '') + ', approver ' + esc(e.approver || '') + ', until ' + esc(e.expires || 'no expiry') + ')</span> <button type="button" class="tech" data-remove-exception="' + i + '">Remove</button></li>'; }).join('');
    var objectOptions = '<option value="">Whole check</option>' + (r.originalAffected || []).map(function (a) { return '<option value="' + esc(nameOf(a)) + '">' + esc(nameOf(a)) + '</option>'; }).join('');
    var expiryDefault = new Date(Date.now() + 365 * 86400000).toISOString().substring(0, 10);
    drawer.innerHTML = '<button class="close" type="button">Close</button>' +
      '<h2>' + esc(r.id) + ' ' + esc(r.title) + '</h2>' +
      '<p><span class="status ' + esc(ef.status) + '">' + esc(statusLabel(ef.status)) + '</span> <span class="sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span> <span class="chip">' + esc(domainLabel(r.domain)) + '</span>' + ((c.license && c.license.length) ? '<span class="chip">Needs ' + esc(c.license.join(' or ')) + '</span>' : '') + '</p>' +
      (ef.reason ? '<p>' + esc(ef.reason) + '</p>' : '') +
      '<h4>Why It Matters</h4><p>' + esc(c.narrative) + '</p>' +
      '<h4>Remediation</h4><p>' + esc(c.remediation) + '</p><p>' + (c.learn ? '<a class="btn" href="' + esc(c.learn) + '" target="_blank" rel="noopener">Microsoft Learn</a> ' : '') + (c.deepLink ? '<a class="btn" href="' + esc(c.deepLink) + '" target="_blank" rel="noopener">Open in Portal</a>' : '') + '</p>' +
      (fw ? '<h4>Frameworks</h4><p class="chips">' + fw + '</p>' : '') +
      (affected ? '<h4>Affected (' + ef.affected.length + ')</h4><ul class="affected">' + affected + '</ul><p><button type="button" id="export-affected">Export Affected CSV</button></p>' : '') +
      '<h4>Exceptions</h4>' + (exList ? '<ul class="exception-list">' + exList + '</ul>' : '<p class="hint">None recorded for this check.</p>') +
      ((ef.status === 'fail' || ef.status === 'acceptedRisk') ? '<div class="form">' +
        '<label>Scope<select id="ex-object">' + objectOptions + '</select></label>' +
        '<label>Expires<input id="ex-expires" type="date" value="' + expiryDefault + '"></label>' +
        '<label class="wide">Justification<textarea id="ex-just" placeholder="Why this risk is accepted and what compensates for it"></textarea></label>' +
        '<label>Owner<input id="ex-owner" type="text" placeholder="Who owns the risk"></label>' +
        '<label>Approver<input id="ex-approver" type="text" placeholder="Who approved it"></label>' +
        '</div><div class="form-actions"><button type="button" class="primary" id="ex-add">Record Exception</button><span class="hint">Re-scores the page now; Save writes it to exceptions.json for every future run.</span></div>' : '') +
      (r.evidence && r.evidence.length ? '<h4 class="tech">Evidence</h4><p class="chips tech">' + r.evidence.map(function (f) { return '<span class="chip">' + esc(f) + '</span>'; }).join('') + '</p>' : '') +
      (r.thresholds && Object.keys(r.thresholds).length ? '<h4 class="tech">Thresholds Used</h4>' + kvRows(r.thresholds, thresholdLabel) : '');
    drawer.classList.add('open');
    drawer.querySelector('.close').addEventListener('click', closeDrawer);
    var ex = $('export-affected'); if (ex) { ex.addEventListener('click', function () { downloadText(r.id + '-affected.csv', toCsv(['Name', 'Detail'], ef.affected.map(function (a) { return [nameOf(a), humanDetail(a && a.detail)]; })), 'text/csv'); }); }
    var add = $('ex-add');
    if (add) {
      add.addEventListener('click', function () {
        var just = ($('ex-just').value || '').trim(); if (!just) { toast('A justification is required.'); $('ex-just').focus(); return; }
        state.exceptions.push({ check: r.id, object: $('ex-object').value || null, justification: just, owner: ($('ex-owner').value || '').trim(), approver: ($('ex-approver').value || '').trim(), expires: $('ex-expires').value || null });
        state.dirty.exceptions = true; recompute(); openDrawer(id); toast('Exception recorded. Save to keep it.');
      });
    }
    Array.prototype.slice.call(drawer.querySelectorAll('[data-remove-exception]')).forEach(function (btn) {
      btn.addEventListener('click', function () {
        var idx = parseInt(btn.getAttribute('data-remove-exception'), 10); var target = mine[idx]; var pos = state.exceptions.indexOf(target);
        if (pos >= 0) { state.exceptions.splice(pos, 1); state.removed.push(target); state.dirty.exceptions = true; recompute(); openDrawer(id); toast('Exception removed. Save to keep the change.'); }
      });
    });
  }
  function closeDrawer() { if (drawer) { drawer.classList.remove('open'); } }
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeDrawer(); } });
  function bindCheckLinks(root) {
    Array.prototype.slice.call((root || document).querySelectorAll('tr[data-check], a[data-check]')).forEach(function (el) {
      if (el.getAttribute('data-bound')) { return; } el.setAttribute('data-bound', '1');
      el.classList.add('clickable');
      el.addEventListener('click', function (e) { if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'BUTTON')) { return; } e.preventDefault(); openDrawer(el.getAttribute('data-check')); });
      el.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target === el) { openDrawer(el.getAttribute('data-check')); } });
      el.setAttribute('tabindex', '0');
    });
  }
  bindCheckLinks(document);

  // ---------- risk register ----------
  var STATUSES = ['Open', 'In progress', 'Accepted', 'Resolved'];
  function registerRows() {
    return data.results.map(function (r) { return { r: r, ef: effective(r) }; }).filter(function (x) { return x.ef.status === 'fail' || x.ef.status === 'acceptedRisk'; })
      .sort(function (a, b) { return (WEIGHT[b.r.severity] || 0) - (WEIGHT[a.r.severity] || 0) || a.r.id.localeCompare(b.r.id); });
  }
  function regEntry(id) { if (!state.register[id]) { state.register[id] = { owner: '', status: '', effort: '', dependency: '', notes: '' }; } return state.register[id]; }
  function renderRegister() {
    var body = $('register-body'); if (!body) { return; }
    var list = registerRows();
    body.innerHTML = list.map(function (x) {
      var r = x.r, e = regEntry(r.id), st = e.status || (x.ef.status === 'acceptedRisk' ? 'Accepted' : 'Open');
      var opts = STATUSES.map(function (s) { return '<option' + (s === st ? ' selected' : '') + '>' + s + '</option>'; }).join('');
      var eff = ['', 'S', 'M', 'L', 'XL'].map(function (s) { return '<option value="' + s + '"' + (s === e.effort ? ' selected' : '') + '>' + (s || 'Effort') + '</option>'; }).join('');
      return '<tr data-check="' + esc(r.id) + '" class="st-' + esc(x.ef.status) + '"><td><code>' + esc(r.id) + '</code><br><span class="tech">' + esc(domainLabel(r.domain)) + '</span></td><td>' + esc(r.title) + (x.ef.affected.length ? '<br><span class="tech">' + x.ef.affected.length + ' affected</span>' : '') + '</td>' +
        '<td><span class="sev ' + esc(r.severity) + '">' + esc(r.severity) + '</span></td><td><span class="status ' + esc(x.ef.status) + '">' + esc(statusLabel(x.ef.status)) + '</span></td>' +
        '<td><input type="text" data-reg="owner" data-id="' + esc(r.id) + '" value="' + esc(e.owner) + '" placeholder="Owner"></td>' +
        '<td><select data-reg="status" data-id="' + esc(r.id) + '">' + opts + '</select></td>' +
        '<td><select data-reg="effort" data-id="' + esc(r.id) + '">' + eff + '</select></td>' +
        '<td><input type="text" data-reg="dependency" data-id="' + esc(r.id) + '" value="' + esc(e.dependency) + '" placeholder="Dependency"></td>' +
        '<td><input type="text" data-reg="notes" data-id="' + esc(r.id) + '" value="' + esc(e.notes) + '" placeholder="Notes"></td></tr>';
    }).join('');
    var count = $('register-count'); if (count) { count.textContent = list.length + ' open or accepted risk(s)'; }
    Array.prototype.slice.call(body.querySelectorAll('[data-reg]')).forEach(function (el) {
      el.addEventListener('change', function () { regEntry(el.getAttribute('data-id'))[el.getAttribute('data-reg')] = el.value; state.dirty.register = true; updateSaveBar(); });
      el.addEventListener('input', function () { regEntry(el.getAttribute('data-id'))[el.getAttribute('data-reg')] = el.value; state.dirty.register = true; updateSaveBar(); });
    });
    bindCheckLinks(body);
  }

  // ---------- settings ----------
  var THIRD_PARTY = ['email', 'edr', 'mfa', 'mdm', 'siem', 'backup'];
  var FRAMEWORKS = ['hipaa', 'pci', 'cmmc', 'soc2', 'iso27001', 'nist-800-171', 'cisa-scuba'];
  function thresholdKeys() { var keys = {}; data.results.forEach(function (r) { Object.keys(r.thresholds || {}).forEach(function (k) { keys[k] = r.thresholds[k]; }); }); Object.keys(state.profile.thresholds || {}).forEach(function (k) { keys[k] = state.profile.thresholds[k]; }); return keys; }
  function renderSettings() {
    var root = $('settings-form'); if (!root) { return; }
    var p = state.profile; p.thresholds = p.thresholds || {}; p.thirdParty = p.thirdParty || {}; p.operations = p.operations || {};
    var th = thresholdKeys();
    var thresholds = Object.keys(th).sort().map(function (k) { var v = p.thresholds[k] != null ? p.thresholds[k] : th[k]; return '<label>' + esc(thresholdLabel(k)) + '<input data-th="' + esc(k) + '" type="' + (typeof v === 'number' ? 'number' : 'text') + '" value="' + esc(v) + '"></label>'; }).join('');
    var third = THIRD_PARTY.map(function (k) { return '<label>' + esc(words(k).replace(/^Edr$/, 'EDR').replace(/^Mfa$/, 'MFA').replace(/^Mdm$/, 'MDM').replace(/^Siem$/, 'SIEM')) + '<input data-tp="' + k + '" type="text" value="' + esc(p.thirdParty[k] && p.thirdParty[k] !== 'none' ? p.thirdParty[k] : '') + '" placeholder="none"></label>'; }).join('');
    var fws = FRAMEWORKS.map(function (k) { return '<label style="flex-direction:row;align-items:center;gap:8px"><input data-fw="' + k + '" type="checkbox"' + ((p.frameworks || []).indexOf(k) >= 0 ? ' checked' : '') + '>' + esc(frameworkLabel(k)) + '</label>'; }).join('');
    root.innerHTML =
      '<div class="settings-group"><h3>Thresholds</h3><p class="hint">Numbers the checks compare against. Blank keeps the catalog default. Applies on the next run.</p><div class="form">' + thresholds + '</div></div>' +
      '<div class="settings-group"><h3>Third-Party Controls</h3><p class="hint">Name the vendor where another product covers the control; the matching checks then read as covered by that vendor.</p><div class="form">' + third + '</div></div>' +
      '<div class="settings-group"><h3>Break-Glass Accounts</h3><div class="form"><label class="wide">One per line (user principal name or display name)<textarea data-bg>' + esc((p.breakGlass || []).join('\n')) + '</textarea></label><label>Last tested<input data-op="breakGlassTestedUtc" type="date" value="' + esc(String(p.operations.breakGlassTestedUtc || '').substring(0, 10)) + '"></label><label>Message Center owner<input data-op="messageCenterOwner" type="text" value="' + esc(p.operations.messageCenterOwner || '') + '"></label></div></div>' +
      '<div class="settings-group"><h3>Frameworks and Audience</h3><div class="form">' + fws + '<label>Audience<select data-p="audience">' + ['technical', 'executive', 'both'].map(function (a) { return '<option' + (a === p.audience ? ' selected' : '') + '>' + a + '</option>'; }).join('') + '</select></label><label>Cadence<select data-p="cadence">' + ['', 'monthly', 'quarterly', 'annual'].map(function (a) { return '<option value="' + a + '"' + (a === (p.cadence || '') ? ' selected' : '') + '>' + (a || 'not set') + '</option>'; }).join('') + '</select></label></div></div>';
    Array.prototype.slice.call(root.querySelectorAll('input, select, textarea')).forEach(function (el) {
      el.addEventListener('change', function () {
        if (el.hasAttribute('data-th')) { var k = el.getAttribute('data-th'); if (el.value === '') { delete p.thresholds[k]; } else { p.thresholds[k] = el.type === 'number' ? Number(el.value) : el.value; } }
        else if (el.hasAttribute('data-tp')) { p.thirdParty[el.getAttribute('data-tp')] = el.value.trim() || 'none'; }
        else if (el.hasAttribute('data-bg')) { p.breakGlass = el.value.split(/\n/).map(function (s) { return s.trim(); }).filter(Boolean); }
        else if (el.hasAttribute('data-op')) { var ok = el.getAttribute('data-op'); p.operations[ok] = el.value ? (el.type === 'date' ? el.value + 'T00:00:00Z' : el.value) : null; }
        else if (el.hasAttribute('data-fw')) { p.frameworks = FRAMEWORKS.filter(function (f) { var box = root.querySelector('[data-fw="' + f + '"]'); return box && box.checked; }); }
        else if (el.hasAttribute('data-p')) { p[el.getAttribute('data-p')] = el.value || null; }
        state.dirty.profile = true; updateSaveBar();
      });
    });
  }

  // ---------- saving ----------
  var canPick = typeof window.showDirectoryPicker === 'function';
  function updateSaveBar() {
    var dirty = state.dirty.exceptions || state.dirty.register || state.dirty.profile;
    Array.prototype.slice.call(document.querySelectorAll('.savebar')).forEach(function (bar) {
      var st = bar.querySelector('.state'); var btn = bar.querySelector('[data-save]'); var pick = bar.querySelector('[data-pick]');
      if (pick) { pick.textContent = state.folder ? 'Client folder: ' + state.folder.name : 'Choose Client Folder'; pick.style.display = canPick ? '' : 'none'; }
      if (btn) { btn.disabled = !dirty; btn.textContent = canPick ? 'Save to Client Folder' : 'Download Files'; }
      if (st) { st.innerHTML = dirty ? '<span class="dirty">Unsaved changes</span>' + (canPick ? '' : ' (this browser cannot write folders; files download instead)') : 'Saved state matches the report' + (canPick ? '' : ' (this browser downloads files on save)'); }
    });
  }
  function toCsv(headers, rows) { var q = function (v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }; return [headers.map(q).join(',')].concat(rows.map(function (r) { return r.map(q).join(','); })).join('\r\n') + '\r\n'; }
  function parseCsv(text) {
    var out = [], row = [], field = '', inQ = false, i, c;
    for (i = 0; i < text.length; i++) {
      c = text[i];
      if (inQ) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else { inQ = false; } } else { field += c; } }
      else if (c === '"') { inQ = true; } else if (c === ',') { row.push(field); field = ''; } else if (c === '\n') { row.push(field); out.push(row); row = []; field = ''; } else if (c !== '\r') { field += c; }
    }
    if (field.length || row.length) { row.push(field); out.push(row); }
    if (!out.length) { return []; }
    var headers = out[0]; return out.slice(1).filter(function (r) { return r.length > 1; }).map(function (r) { var o = {}; headers.forEach(function (h, j) { o[h] = r[j] == null ? '' : r[j]; }); return o; });
  }
  function downloadText(name, text, type) { var blob = new Blob([text], { type: type || 'application/json' }), url = URL.createObjectURL(blob), a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); }
  function exceptionsDocument(existing) {
    // Working list wins; entries the file gained since the report was built are kept unless removed here.
    var snapshot = data.exceptions.map(key), removed = state.removed.map(key), working = state.exceptions.map(key);
    var extra = (existing || []).filter(function (e) { var k = key(e); return snapshot.indexOf(k) < 0 && removed.indexOf(k) < 0 && working.indexOf(k) < 0; });
    return { exceptions: state.exceptions.concat(extra).map(function (e) { return { check: e.check, object: e.object || null, justification: e.justification || '', owner: e.owner || '', approver: e.approver || '', expires: e.expires || null }; }) };
    function key(e) { return (e.check || '') + '|' + (e.object || ''); }
  }
  function registerCsv(existingRows) {
    var byRow = {}; (existingRows || []).forEach(function (r) { if (r.ID) { byRow[r.ID] = r; } });
    var headers = ['ID', 'Workstream', 'Finding', 'Evidence', 'Likelihood 1-5', 'Impact 1-5', 'Risk', 'Effort S/M/L/XL', 'Dependency', 'Quick win', 'Bucket', 'Owner', 'Status', 'Remediation', 'Learn', 'Checked', 'Licence', 'Notes'];
    var lvl = { Critical: 5, High: 4, Medium: 3, Low: 2 }, bucket = { Critical: 'Stop the bleeding', High: 'Foundations', Medium: 'Program workstreams', Low: 'Later' };
    var seen = {};
    var lines = registerRows().map(function (x) {
      var r = x.r, e = regEntry(r.id), old = byRow[r.id] || {}, l = lvl[r.severity] || 3, c = data.catalog[r.id] || {}; seen[r.id] = true;
      var finding = r.title + (x.ef.affected.length ? ' (' + x.ef.affected.length + ' affected: ' + x.ef.affected.slice(0, 5).map(nameOf).join(', ') + (x.ef.affected.length > 5 ? ', ...' : '') + ')' : '');
      var status = e.status || (x.ef.status === 'acceptedRisk' ? 'Accepted' : (old.Status && old.Status !== 'Resolved' ? old.Status : 'Open'));
      return [r.id, domainLabel(r.domain), finding, (r.evidence || []).join('; '), l, l, l * l, e.effort || old['Effort S/M/L/XL'] || '', e.dependency || old.Dependency || '', (x.ef.status === 'fail' && x.ef.affected.length <= 5 && (r.severity === 'Low' || r.severity === 'Medium')) ? 'Y' : '', bucket[r.severity] || 'Later', e.owner || old.Owner || '', status, c.remediation || '', c.learn || '', r.checkedUtc || data.meta.generatedUtc || '', data.meta.licenceId || old.Licence || '', e.notes || old.Notes || ''];
    });
    (existingRows || []).forEach(function (old) { if (old.ID && !seen[old.ID] && old.Status !== 'Resolved') { lines.push(headers.map(function (h) { return h === 'Status' ? 'Resolved' : (old[h] || ''); })); } });
    return toCsv(headers, lines);
  }
  function profileDocument(existing) {
    var doc = existing && typeof existing === 'object' ? existing : {};
    var p = state.profile;
    ['thresholds', 'thirdParty', 'breakGlass', 'frameworks', 'audience', 'cadence'].forEach(function (k) { if (p[k] != null) { doc[k] = p[k]; } });
    doc.operations = Object.assign({}, doc.operations || {}, p.operations || {});
    doc.updatedUtc = new Date().toISOString();
    if (!doc.version) { doc.version = 1; }
    return doc;
  }
  async function readFile(dir, name) { try { var fh = await dir.getFileHandle(name); var f = await fh.getFile(); return await f.text(); } catch (e) { return null; } }
  async function writeFile(dir, name, text) { var fh = await dir.getFileHandle(name, { create: true }); var w = await fh.createWritable(); await w.write(text); await w.close(); }
  async function pickFolder() {
    try {
      var dir = await window.showDirectoryPicker({ mode: 'readwrite', id: 'tenantkeep-client' });
      var profileText = await readFile(dir, 'profile.json');
      if (profileText && data.meta.tenantId) {
        try { var pr = JSON.parse(profileText); if (pr.tenantId && String(pr.tenantId).toLowerCase() !== String(data.meta.tenantId).toLowerCase()) { toast('That folder belongs to tenant ' + pr.tenantId + ', not this report. Pick the right client folder.'); return; } } catch (e) { /* unreadable profile: allow */ }
      }
      state.folder = dir; updateSaveBar(); toast('Client folder: ' + dir.name);
    } catch (e) { if (e && e.name !== 'AbortError') { toast('Could not open the folder: ' + e.message); } }
  }
  async function save() {
    var files = {};
    if (canPick) {
      if (!state.folder) { await pickFolder(); if (!state.folder) { return; } }
      var dir = state.folder;
      try {
        if (state.dirty.exceptions) { var exText = await readFile(dir, 'exceptions.json'); var existing = []; try { var exDoc = exText ? JSON.parse(exText) : null; existing = exDoc ? (Array.isArray(exDoc) ? exDoc : (exDoc.exceptions || [])) : []; } catch (e) { existing = []; } await writeFile(dir, 'exceptions.json', JSON.stringify(exceptionsDocument(existing), null, 2) + '\n'); files['exceptions.json'] = 1; }
        if (state.dirty.register || state.dirty.exceptions) { var csvText = await readFile(dir, 'findings.csv'); await writeFile(dir, 'findings.csv', registerCsv(csvText ? parseCsv(csvText) : [])); files['findings.csv'] = 1; }
        if (state.dirty.profile) { var pText = await readFile(dir, 'profile.json'); var pDoc = null; try { pDoc = pText ? JSON.parse(pText) : null; } catch (e) { pDoc = null; } await writeFile(dir, 'profile.json', JSON.stringify(profileDocument(pDoc), null, 2) + '\n'); files['profile.json'] = 1; }
      } catch (e) { toast('Save failed: ' + e.message); return; }
    } else {
      if (state.dirty.exceptions) { downloadText('exceptions.json', JSON.stringify(exceptionsDocument([]), null, 2) + '\n'); files['exceptions.json'] = 1; }
      if (state.dirty.register || state.dirty.exceptions) { downloadText('findings.csv', registerCsv(data.register), 'text/csv'); files['findings.csv'] = 1; }
      if (state.dirty.profile) { downloadText('profile.json', JSON.stringify(profileDocument(JSON.parse(JSON.stringify(data.profile || {}))), null, 2) + '\n'); files['profile.json'] = 1; }
    }
    data.exceptions = state.exceptions.slice(); state.removed = []; state.dirty = { exceptions: false, register: false, profile: false };
    recompute(); toast('Saved ' + Object.keys(files).join(', ') + (canPick ? ' to ' + state.folder.name : '') + '. The next run reads them.');
  }
  Array.prototype.slice.call(document.querySelectorAll('[data-pick]')).forEach(function (b) { b.addEventListener('click', pickFolder); });
  Array.prototype.slice.call(document.querySelectorAll('[data-save]')).forEach(function (b) { b.addEventListener('click', save); });
  window.addEventListener('beforeunload', function (e) { if (state.dirty.exceptions || state.dirty.register || state.dirty.profile) { e.preventDefault(); e.returnValue = ''; } });

  var exportAll = $('export-checks');
  if (exportAll) { exportAll.addEventListener('click', function () { downloadText('checks.csv', toCsv(['ID', 'Domain', 'Title', 'Status', 'Severity', 'Affected', 'Reason'], data.results.map(function (r) { var ef = effective(r); return [r.id, domainLabel(r.domain), r.title, statusLabel(ef.status), r.severity, ef.affected.length, ef.reason]; })), 'text/csv'); }); }

  // Humanise the server-rendered detail cells once.
  Array.prototype.slice.call(document.querySelectorAll('[data-human]')).forEach(function (el) { el.textContent = humanDetail(el.textContent); });
  renderSettings();
  recompute();
})();
