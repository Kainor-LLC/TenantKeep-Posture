// Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
// The licensing advisor, in the page: the same search as Get-PostureLicenseAdvice, so goals and vendor toggles
// recompute the options without saving anything. A Pester test runs this file under node on the same inputs as the
// PowerShell and compares the answers; change one, change both.
var tkLicenseAdvice = (function () {
  'use strict';
  function advise(data, state) {
    var feat = {}; data.features.forEach(function (f) { feat[f.id] = f; });
    var owned = {}; data.owned.forEach(function (id) { owned[id] = true; });
    var vendorOf = {};
    data.features.forEach(function (f) { var v = f.coveredBy && state.thirdParty[f.coveredBy]; if (v && v !== 'none') { vendorOf[f.id] = v; } });
    var have = {}; Object.keys(owned).forEach(function (k) { have[k] = true; }); Object.keys(vendorOf).forEach(function (k) { have[k] = true; });
    var isSecurity = function (id) { return !feat[id] || feat[id].kind !== 'value'; };
    var unmet = function (g, set) { return g.needs.filter(function (grp) { return !grp.some(function (x) { return set[x]; }); }); };
    var chosen = data.goals.filter(function (g) { return state.goals.length ? state.goals.indexOf(g.id) >= 0 : g.core; });
    var groups = []; chosen.forEach(function (g) { unmet(g, have).forEach(function (grp) { groups.push(grp); }); });
    var allGroups = []; chosen.forEach(function (g) { g.needs.forEach(function (grp) { allGroups.push(grp); }); });
    var fits = function (b) { return !(b.seatCap && state.seats > b.seatCap); };
    var covers = function (base, bundles, need) {
      var set = {}; base.forEach(function (x) { set[x] = true; }); bundles.forEach(function (b) { b.features.forEach(function (x) { set[x] = true; }); });
      return need.every(function (grp) { return grp.some(function (x) { return set[x]; }); });
    };
    var unique = function (combo) { var s = {}; combo.forEach(function (b) { b.features.forEach(function (x) { s[x] = true; }); }); return Object.keys(s).length; };
    var search = function (base, max, noRedundant, need, skusHeld) {
      var held = skusHeld || data.ownedSkus || [];
      var baseSet = {}; base.forEach(function (x) { baseSet[x] = true; });
      var cands = data.bundles.filter(function (b) { return b.kind === 'addon' && fits(b) && b.features.some(function (x) { return !baseSet[x] && isSecurity(x); }); });
      cands = cands.filter(function (b) { return !(b.requiresBase && b.requiresBase.length) || b.requiresBase.some(function (s) { return held.indexOf(s) >= 0; }); });
      if (noRedundant) { cands = cands.filter(function (b) { return !b.features.some(function (x) { return vendorOf[x] && !owned[x]; }); }); }
      if (covers(base, [], need)) { return []; }
      for (var size = 1; size <= max; size++) {
        var combos = [], i, j, k;
        if (size === 1) { for (i = 0; i < cands.length; i++) { combos.push([cands[i]]); } }
        if (size === 2) { for (i = 0; i < cands.length; i++) { for (j = i + 1; j < cands.length; j++) { combos.push([cands[i], cands[j]]); } } }
        if (size === 3) { for (i = 0; i < cands.length; i++) { for (j = i + 1; j < cands.length; j++) { for (k = j + 1; k < cands.length; k++) { combos.push([cands[i], cands[j], cands[k]]); } } } }
        var ok = combos.filter(function (c) { return covers(base, c, need); });
        ok.sort(function (a, b) { return (unique(a) - unique(b)) || (a.filter(function (x) { return !x.seatCap; }).length - b.filter(function (x) { return !x.seatCap; }).length); });
        if (ok.length) { return ok[0]; }
      }
      return null;
    };
    var describe = function (kind, title, skus) {
      var brought = {}; skus.forEach(function (b) { b.features.forEach(function (x) { brought[x] = true; }); });
      var order = data.features.map(function (f) { return f.id; });
      return {
        kind: kind, title: title,
        skus: skus.map(function (b) { return { sku: b.sku, name: b.name, verify: b.verify || null }; }),
        adds: order.filter(function (id) { return brought[id] && !owned[id] && !vendorOf[id] && isSecurity(id); }).map(function (id) { return feat[id].name; }),
        redundant: order.filter(function (id) { return brought[id] && !owned[id] && vendorOf[id]; }).map(function (id) { return { name: feat[id].name, vendor: vendorOf[id] }; }),
        alsoIncludes: order.filter(function (id) { return brought[id] && !owned[id] && !isSecurity(id); }).map(function (id) { return feat[id].name; })
      };
    };
    var options = [];
    if (groups.length) {
      var addOnly = search(Object.keys(have), 3, false, groups);
      if (addOnly) { options.push(describe('addons', 'Add to what you have', addOnly)); }
      if (Object.keys(vendorOf).length) {
        var lean = search(Object.keys(have), 3, true, groups);
        var key = function (c) { return (c || []).map(function (b) { return b.sku; }).join(','); };
        if (lean && key(lean) !== key(addOnly)) { options.push(describe('addons', 'Add only what your other products do not already cover', lean)); }
      }
      var suites = [];
      data.bundles.forEach(function (s) {
        if (s.kind !== 'suite' || !fits(s)) { return; }
        if (!s.features.some(function (x) { return !owned[x] && isSecurity(x); })) { return; }
        var extra = search(s.features.concat(Object.keys(vendorOf)), 2, false, allGroups, [s.sku]);
        if (extra === null) { return; }
        suites.push({ suite: s, extra: extra });
      });
      suites.sort(function (a, b) { return (a.extra.length - b.extra.length) || (a.suite.features.length - b.suite.features.length); });
      suites.slice(0, 2).forEach(function (so) {
        options.push(describe('suite', 'Move to ' + so.suite.name + (so.extra.length ? ' with ' + so.extra.map(function (b) { return b.name; }).join(' and ') : ''), [so.suite].concat(so.extra)));
      });
    }
    return {
      goals: chosen.map(function (g) { return g.id; }),
      met: groups.length === 0,
      missing: groups.map(function (grp) { return grp.map(function (x) { return feat[x].name; }); }),
      options: options
    };
  }
  return advise;
}());
if (typeof module === 'object' && module.exports) { module.exports = tkLicenseAdvice; }
