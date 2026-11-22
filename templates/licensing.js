// Copyright (c) 2026 Kainor LLC. Source-available, see LICENSE.md.
// The licensing advisor, in the page: the same combinations as Get-PostureLicenseAdvice, so ticking a goal or naming
// another product recomputes the recommendation without saving anything. The page holds no price and chooses on
// function alone: the fewest licences, then keeping the suite the tenant holds, then the least overlap with other
// products, then the order of the data. A Pester test runs this file under node on the same inputs as the PowerShell
// (without a price file) and compares the answers; change one, change both.
var tkLicenseAdvice = (function () {
  'use strict';
  function advise(data, state) {
    var feat = {}; data.features.forEach(function (f) { feat[f.id] = f; });
    var order = data.features.map(function (f) { return f.id; });
    var owned = {}; data.owned.forEach(function (id) { owned[id] = true; });
    var vendorOf = {};
    data.features.forEach(function (f) { var v = f.coveredBy && state.thirdParty[f.coveredBy]; if (v && v !== 'none') { vendorOf[f.id] = v; } });
    var have = {}; Object.keys(owned).forEach(function (k) { have[k] = true; }); Object.keys(vendorOf).forEach(function (k) { have[k] = true; });
    var isSecurity = function (id) { return !feat[id] || feat[id].kind !== 'value'; };
    var unmet = function (g, set) { return g.needs.filter(function (grp) { return !grp.some(function (x) { return set[x]; }); }); };
    var chosen = data.goals.filter(function (g) { return state.goals.length ? state.goals.indexOf(g.id) >= 0 : g.core; });
    var groups = []; chosen.forEach(function (g) { unmet(g, have).forEach(function (grp) { groups.push(grp); }); });
    // Every chosen goal's groups, met or not, and those of every goal the tenant meets today: a suite replaces the
    // current one, so it must cover the chosen goals itself and must not take away a goal that is met now.
    var chosenIds = {}; chosen.forEach(function (g) { chosenIds[g.id] = true; });
    var allGroups = []; chosen.forEach(function (g) { g.needs.forEach(function (grp) { allGroups.push(grp); }); });
    data.goals.forEach(function (g) { if (!chosenIds[g.id] && unmet(g, have).length === 0) { g.needs.forEach(function (grp) { allGroups.push(grp); }); } });
    var fits = function (b) { return !(b.seatCap && state.seats > b.seatCap); };
    var betterCover = function (a, b) {
      if (b === null) { return true; }
      if (a.idx.length !== b.idx.length) { return a.idx.length < b.idx.length; }
      if (a.brings !== b.brings) { return a.brings < b.brings; }
      if (a.uncapped !== b.uncapped) { return a.uncapped < b.uncapped; }
      for (var i = 0; i < a.idx.length; i++) { if (a.idx[i] !== b.idx[i]) { return a.idx[i] < b.idx[i]; } }
      return false;
    };
    // The add-ons that close every gap in need on top of base: every way of covering the first open group is tried
    // in turn, so the answer is the best one and not the first found.
    var cover = function (base, need, skusHeld, noRedundant) {
      var baseSet = {}; base.forEach(function (x) { baseSet[x] = true; });
      var open = need.filter(function (grp) { return !grp.some(function (x) { return baseSet[x]; }); });
      if (!open.length) { return { items: [] }; }
      var cands = [];
      data.bundles.forEach(function (b) {
        if (b.kind !== 'addon' || !fits(b)) { return; }
        if (b.requiresBase && b.requiresBase.length && !b.requiresBase.some(function (s) { return skusHeld.indexOf(s) >= 0; })) { return; }
        if (noRedundant && b.features.some(function (x) { return vendorOf[x] && !owned[x]; })) { return; }
        var hits = open.map(function (grp) { return grp.some(function (x) { return b.features.indexOf(x) >= 0; }); });
        if (hits.some(function (h) { return h; })) { cands.push({ bundle: b, hits: hits }); }
      });
      var best = null, seen = {}, stack = [{ idx: [], covered: open.map(function () { return false; }) }];
      while (stack.length) {
        var n = stack.pop();
        if (best && n.idx.length > best.idx.length) { continue; }
        var g = n.covered.indexOf(false);
        if (g < 0) {
          var brought = {}; n.idx.forEach(function (i) { cands[i].bundle.features.forEach(function (x) { brought[x] = true; }); });
          n.brings = Object.keys(brought).length;
          n.uncapped = n.idx.filter(function (i) { return !cands[i].bundle.seatCap; }).length;
          if (betterCover(n, best)) { best = n; }
          continue;
        }
        for (var c = cands.length - 1; c >= 0; c--) {
          if (!cands[c].hits[g] || n.idx.indexOf(c) >= 0) { continue; }
          var idx = n.idx.concat([c]).sort(function (x, y) { return x - y; });
          var key = idx.join(',');
          if (seen[key]) { continue; }
          seen[key] = true;
          var hitsC = cands[c].hits;
          stack.push({ idx: idx, covered: n.covered.map(function (v, i) { return v || hitsC[i]; }) });
        }
      }
      if (best === null) { return null; }
      return { items: best.idx.map(function (i) { return cands[i].bundle; }) };
    };
    // The same, with what the add-ons themselves need (ID Governance needs Entra ID P1, the Intune Suite needs Intune).
    var coverAll = function (base, need, skusHeld, noRedundant) {
      var needList = need.slice(), found = null;
      for (var round = 0; round < 4; round++) {
        found = cover(base, needList, skusHeld, noRedundant);
        if (found === null) { return null; }
        var set = {}; base.forEach(function (x) { set[x] = true; });
        found.items.forEach(function (b) { b.features.forEach(function (x) { set[x] = true; }); });
        var lacking = {};
        found.items.forEach(function (b) { b.features.forEach(function (x) { ((feat[x] && feat[x].requires) || []).forEach(function (r) { if (r && !set[r]) { lacking[r] = true; } }); }); });
        var list = Object.keys(lacking).sort();
        if (!list.length) { return found; }
        list.forEach(function (r) { needList.push([r]); });
      }
      return found;
    };
    var names = function (list) { var n = list.map(function (b) { return b.name; }); return n.length <= 1 ? n.join('') : n.slice(0, n.length - 1).join(', ') + ' and ' + n[n.length - 1]; };
    var overlapCount = function (list) { var s = {}; list.forEach(function (b) { b.features.forEach(function (x) { if (vendorOf[x] && !owned[x]) { s[x] = true; } }); }); return Object.keys(s).length; };
    var heldSkus = data.ownedSkus || [];
    var heldBundles = data.bundles.filter(function (b) { return heldSkus.indexOf(b.sku) >= 0; });
    var heldSuites = heldBundles.filter(function (b) { return b.kind === 'suite' && !b.companion; });
    var heldCompanions = heldBundles.filter(function (b) { return b.kind === 'suite' && b.companion; });
    var heldAddons = heldBundles.filter(function (b) { return b.kind === 'addon'; });
    var mainSuite = null; heldSuites.forEach(function (b) { if (mainSuite === null || b.features.length > mainSuite.features.length) { mainSuite = b; } });
    var candidateSuites = data.bundles.filter(function (s) { return s.kind === 'suite' && !s.companion && fits(s) && heldSkus.indexOf(s.sku) < 0 && s.features.some(function (x) { return !owned[x] && isSecurity(x); }); });

    // Step one: every combination that works. Step two: the one to recommend.
    var made = [];
    var addPlan = function (kind, suite, items, replaced, kept) {
      var all = (suite ? [suite] : []).concat(items);
      made.push({ kind: kind, suite: suite, items: items, replaced: replaced, kept: kept, count: all.length, kindOrder: kind === 'suite' ? 1 : 0, overlap: overlapCount(all), order: made.length });
    };
    var skuKey = function (c) { return (c ? c.items : []).map(function (b) { return b.sku; }).join(','); };
    if (groups.length) {
      var addOnly = coverAll(Object.keys(have), groups, heldSkus, false);
      if (addOnly && addOnly.items.length) { addPlan('addons', null, addOnly.items, [], []); }
      if (Object.keys(vendorOf).length) {
        var lean = coverAll(Object.keys(have), groups, heldSkus, true);
        if (lean && lean.items.length && skuKey(lean) !== skuKey(addOnly)) { addPlan('addons', null, lean.items, [], []); }
      }
      candidateSuites.forEach(function (s) {
        var suiteSet = {}; s.features.forEach(function (x) { suiteSet[x] = true; });
        var kept = heldAddons.filter(function (b) { return (!(b.requiresBase && b.requiresBase.length) || b.requiresBase.indexOf(s.sku) >= 0) && b.features.some(function (x) { return !suiteSet[x]; }); });
        var keptCompanions = heldCompanions.filter(function (b) { return b.features.some(function (x) { return !suiteSet[x]; }); });
        var replaced = (mainSuite ? [mainSuite] : []).concat(heldCompanions.filter(function (b) { return keptCompanions.indexOf(b) < 0; }), heldAddons.filter(function (b) { return kept.indexOf(b) < 0; }));
        var base = s.features.concat(Object.keys(vendorOf));
        kept.forEach(function (b) { base = base.concat(b.features); });
        keptCompanions.forEach(function (b) { base = base.concat(b.features); });
        var extra = coverAll(base, allGroups, [s.sku].concat(kept.map(function (b) { return b.sku; })), false);
        if (extra === null) { return; }
        addPlan('suite', s, extra.items, replaced, kept.concat(keptCompanions));
      });
    }
    var top = null;
    made.forEach(function (m) {
      var better = top === null ? true
        : m.count !== top.count ? m.count < top.count
          : m.kindOrder !== top.kindOrder ? m.kindOrder < top.kindOrder
            : m.overlap !== top.overlap ? m.overlap < top.overlap
              : false;
      if (better) { top = m; }
    });

    // The recommendation, in terms of function only: each licence with the goals it is there for and what it brings.
    var recommended = null, prerequisite = [];
    if (top) {
      var all = (top.suite ? [top.suite] : []).concat(top.items);
      var brought = {}; all.forEach(function (b) { b.features.forEach(function (x) { brought[x] = true; }); });
      var licences = all.map(function (b) {
        var mine = {}; b.features.forEach(function (x) { mine[x] = true; });
        return {
          sku: b.sku, name: b.name, role: (top.suite && b === top.suite) ? 'moveTo' : 'add', verify: b.verify || null,
          covers: chosen.filter(function (g) { return unmet(g, have).some(function (grp) { return grp.some(function (x) { return mine[x]; }); }); }).map(function (g) { return g.name; }),
          brings: order.filter(function (id) { return mine[id] && !owned[id] && !vendorOf[id] && isSecurity(id); }).map(function (id) { return feat[id].name; }),
          neededBy: data.features.filter(function (f) { return f.requires && f.requires.length && brought[f.id] && !mine[f.id] && f.requires.some(function (r) { return mine[r] && !have[r]; }); }).map(function (f) { return f.name; })
        };
      });
      var after = {}; Object.keys(brought).forEach(function (x) { after[x] = true; });
      top.kept.forEach(function (b) { b.features.forEach(function (x) { after[x] = true; }); });
      heldBundles.forEach(function (b) { if (top.replaced.indexOf(b) < 0) { b.features.forEach(function (x) { after[x] = true; }); } });
      recommended = {
        kind: top.kind,
        title: top.kind === 'suite' ? 'Move to ' + top.suite.name + (top.items.length ? ' with ' + names(top.items) : '') : 'Add ' + names(top.items) + (mainSuite ? ' to ' + mainSuite.name : ' to what you have'),
        licences: licences,
        replaces: top.replaced.map(function (b) { return { name: b.name, by: top.suite.name }; }),
        keeps: top.kept.map(function (b) { return b.name; }),
        noLonger: order.filter(function (id) { return !after[id] && top.replaced.some(function (b) { return b.features.indexOf(id) >= 0; }); }).map(function (id) { return feat[id].name; }),
        redundant: order.filter(function (id) { return brought[id] && !owned[id] && vendorOf[id]; }).map(function (id) { return { name: feat[id].name, vendor: vendorOf[id] }; }),
        alsoIncludes: order.filter(function (id) { return brought[id] && !owned[id] && !isSecurity(id); }).map(function (id) { return feat[id].name; })
      };
      var seenNote = {};
      Object.keys(brought).forEach(function (x) {
        ((feat[x] && feat[x].requires) || []).forEach(function (r) { if (!have[r] && !brought[r]) { var note = feat[x].name + ' needs ' + feat[r].name + '.'; if (!seenNote[note]) { seenNote[note] = true; prerequisite.push(note); } } });
      });
    }
    // Licences the tenant holds today that overlap: everything one brings is also in another it holds.
    var heldOverlap = [];
    heldBundles.forEach(function (small) {
      if (!small.features.length) { return; }
      var found = false;
      heldBundles.forEach(function (big) {
        if (found || big.kind !== 'suite' || big === small || big.features.length <= small.features.length) { return; }
        if (small.features.every(function (x) { return big.features.indexOf(x) >= 0; })) { heldOverlap.push({ licence: small.name, includedIn: big.name }); found = true; }
      });
    });
    // Each gap once, in the order met: two goals that lack the same feature are one thing to buy.
    var missingSeen = {}, missingOnce = [];
    groups.forEach(function (grp) { var k = grp.join('|'); if (!missingSeen[k]) { missingSeen[k] = true; missingOnce.push(grp.map(function (x) { return feat[x].name; })); } });
    return {
      goals: chosen.map(function (g) { return g.id; }),
      met: groups.length === 0,
      missing: missingOnce,
      recommended: recommended,
      heldOverlap: heldOverlap,
      prerequisite: prerequisite
    };
  }
  return advise;
}());
if (typeof module === 'object' && module.exports) { module.exports = tkLicenseAdvice; }
