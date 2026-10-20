(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const svg = (name, cls = 'icon') => `<svg class="${cls}"><use href="#i-${name}"></use></svg>`;
  const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const severityColor = { critical: '#ff5d73', high: '#ffb454', medium: '#f4d35e', low: '#6ea8fe' };
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const fmtTime = (iso) => {
    if (!iso) return '—';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    return `${String(date.getUTCHours()).padStart(2, '0')}:${String(date.getUTCMinutes()).padStart(2, '0')}:${String(date.getUTCSeconds()).padStart(2, '0')} UTC`;
  };

  const fmtDay = (iso) => {
    if (!iso) return '—';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
  };

  const titleCase = (value) => String(value || '').replace(/(^|[\s-])\w/g, (match) => match.toUpperCase());
  const tacticLabel = (value) => ({
    'command-and-control': 'Command & Control',
    'privilege-escalation': 'Privilege escalation',
    'credential-access': 'Credential access',
    'lateral-movement': 'Lateral movement'
  }[value] || titleCase(String(value || '').replace(/-/g, ' ')));

  let toastTimer;
  function toast(message) {
    const node = $('#toast');
    if (!node) return;
    node.textContent = message;
    node.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => node.classList.remove('show'), 2600);
  }

  function revealOnScroll() {
    const items = $$('.reveal');
    if (reduceMotion || !('IntersectionObserver' in window)) {
      items.forEach((item) => item.classList.add('in'));
      return;
    }
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.08 });
    items.forEach((item) => observer.observe(item));
  }

  function initHeader() {
    const menuButton = $('#menu-btn');
    const nav = $('#site-nav');
    if (menuButton && nav) {
      menuButton.addEventListener('click', () => {
        const open = menuButton.getAttribute('aria-expanded') === 'true';
        menuButton.setAttribute('aria-expanded', String(!open));
        nav.classList.toggle('is-open', !open);
      });
      nav.addEventListener('click', (event) => {
        if (event.target.closest('a')) {
          menuButton.setAttribute('aria-expanded', 'false');
          nav.classList.remove('is-open');
        }
      });
    }

    const links = $$('.site-nav a');
    const sections = links.map((link) => document.querySelector(link.getAttribute('href'))).filter(Boolean);
    if (!('IntersectionObserver' in window)) return;
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        links.forEach((link) => link.classList.toggle('is-active', link.getAttribute('href') === `#${entry.target.id}`));
      });
    }, { rootMargin: '-40% 0px -55% 0px' });
    sections.forEach((section) => observer.observe(section));
  }

  function initDialogs() {
    $$('dialog').forEach((dialog) => {
      $$('[data-close-dialog]', dialog).forEach((button) => {
        button.addEventListener('click', () => dialog.close());
      });
      dialog.addEventListener('click', (event) => {
        if (event.target === dialog) dialog.close();
      });
    });
  }

  async function initAtor() {
    const shell = $('#ator-demo');
    if (!shell) return;
    let data;
    try {
      const response = await fetch('assets/data/ator.json');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } catch (error) {
      $('#ator-kpis').innerHTML = `<div class="kpi" style="grid-column:1/-1"><div class="kpi-label">Data unavailable</div><div class="kpi-value"><strong>—</strong><span>could not load the replay</span></div></div>`;
      return;
    }

    const state = { q: '', severity: '', host: '', chainHost: '1', reportLoaded: false };
    const detections = [...data.detections].sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.id - b.id);
    const hostById = Object.fromEntries(data.hosts.map((host) => [host.id, host]));

    const runTime = new Date(data.report_generated_at).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC'
    }).replace(',', '');
    $('#ator-run-time').textContent = `${runTime} UTC`;
    const risk = data.risk || {};
    const riskPill = $('#ator-risk');
    riskPill.textContent = risk.risk_level || 'RISK';
    riskPill.classList.remove('sev-critical', 'sev-high', 'sev-medium', 'sev-low');
    if ((risk.risk_level || '').toLowerCase() === 'high') riskPill.style.borderColor = 'rgba(255,180,84,.35)';
    $('#ator-score').textContent = risk.score ?? '—';

    const totalDetections = data.stats?.total ?? detections.length;
    const kpis = [
      { label: 'Detections', value: totalDetections, suffix: 'findings', hint: `${data.stats?.counts?.critical ?? 0} critical · ${data.stats?.counts?.high ?? 0} high` },
      { label: 'Endpoints', value: data.stats?.hosts_active ?? data.hosts.length, suffix: 'active', hint: 'Windows · Linux · Docker' },
      { label: 'ATT&CK stages', value: risk.attack_stages_observed ?? 0, suffix: 'reconstructed', hint: 'kill-chain coverage' },
      { label: 'Evidence', value: data.stats?.manifests ?? 0, suffix: 'manifests', hint: 'SHA-256 integrity' }
    ];
    $('#ator-kpis').innerHTML = kpis.map((kpi) => `
      <div class="kpi">
        <div class="kpi-label">${esc(kpi.label)}</div>
        <div class="kpi-value"><strong>${esc(kpi.value)}</strong><span>${esc(kpi.suffix)}</span></div>
        <div class="kpi-hint">${esc(kpi.hint)}</div>
      </div>`).join('');

    $('#hero-detections').textContent = totalDetections;
    $('#hero-stages').textContent = risk.attack_stages_observed ?? 0;
    $('#tab-det-count').textContent = totalDetections;

    const heroFeed = $('#hero-feed');
    heroFeed.innerHTML = detections.slice(0, 3).map((detection) => `
      <div class="hero-feed-row">
        <i class="${esc(detection.severity)}"></i>
        <span>${esc(detection.rule_name)}</span>
        <time>${esc(fmtTime(detection.detected_at_utc).replace(' UTC', ''))}</time>
      </div>`).join('');

    const counts = data.stats?.counts || {};
    const donutTotal = Object.values(counts).reduce((sum, value) => sum + Number(value || 0), 0) || totalDetections;
    const radius = 48;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const segments = ['critical', 'high', 'medium', 'low'].map((severity) => {
      const value = Number(counts[severity] || 0);
      const length = donutTotal ? (value / donutTotal) * circumference : 0;
      const segment = `<circle cx="60" cy="60" r="${radius}" stroke="${severityColor[severity]}" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" opacity="${value ? 1 : 0}"></circle>`;
      offset += length;
      return segment;
    }).join('');
    $('#ator-donut').innerHTML = `
      <div class="donut">
        <svg viewBox="0 0 120 120" aria-hidden="true">
          <circle cx="60" cy="60" r="${radius}" stroke="rgba(148,178,214,.08)"></circle>
          ${segments}
        </svg>
        <div class="donut-center"><strong>${donutTotal}</strong><span>findings</span></div>
      </div>
      <div class="donut-legend">
        ${['critical', 'high', 'medium', 'low'].map((severity) => `
          <div class="legend-row"><i style="background:${severityColor[severity]}"></i><span>${titleCase(severity)}</span><b>${Number(counts[severity] || 0)}</b></div>`).join('')}
      </div>`;

    const tacticCounts = {};
    detections.forEach((detection) => {
      (detection.tactics || []).forEach((tactic) => {
        const key = tactic.short || tactic.name;
        tacticCounts[key] = (tacticCounts[key] || 0) + 1;
      });
    });
    const tacticRows = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]);
    const tacticMax = Math.max(1, ...tacticRows.map(([, value]) => value));
    $('#ator-tactics').innerHTML = tacticRows.length ? tacticRows.map(([tactic, value]) => `
      <div class="tactic-row"><span>${esc(tacticLabel(tactic))}</span><div class="tactic-track"><div class="tactic-fill" style="width:${(value / tacticMax) * 100}%"></div></div><b>${value}</b></div>`).join('') : '<p class="table-hint">No tactics recorded.</p>';

    const recentRows = (items) => items.map((detection) => `
      <button class="mini-row" type="button" data-det-id="${detection.id}">
        <i class="dot" style="background:${severityColor[detection.severity] || '#6ea8fe'}"></i>
        <span class="mini-name">${esc(detection.rule_name)}</span>
        <span class="mini-host">${esc(detection.hostname)}</span>
        <time>${esc(fmtTime(detection.detected_at_utc).replace(' UTC', ''))}</time>
      </button>`).join('');
    $('#ator-recent').innerHTML = recentRows(detections.slice(0, 5));

    const hostOptions = data.hosts.map((host) => `<option value="${host.id}">${esc(host.hostname)}</option>`).join('');
    $('#det-host').insertAdjacentHTML('beforeend', hostOptions);
    $('#chain-host').innerHTML = hostOptions;
    $('#chain-host').value = state.chainHost;

    function filteredDetections() {
      const query = state.q.trim().toLowerCase();
      return detections.filter((detection) => {
        if (state.severity && detection.severity !== state.severity) return false;
        if (state.host && String(detection.host_id) !== String(state.host)) return false;
        if (!query) return true;
        const haystack = [
          detection.rule_name, detection.hostname, detection.technique_id, detection.technique_name,
          ...(detection.tactics || []).map((tactic) => `${tactic.short} ${tactic.name}`)
        ].join(' ').toLowerCase();
        return haystack.includes(query);
      });
    }

    function renderDetections() {
      const items = filteredDetections();
      $('#det-count').textContent = `${items.length} finding${items.length === 1 ? '' : 's'}`;
      if (!items.length) {
        $('#ator-dets').innerHTML = `<tr><td colspan="6"><p class="table-hint" style="padding:14px 0">No findings match these filters.</p></td></tr>`;
        return;
      }
      $('#ator-dets').innerHTML = items.map((detection) => `
        <tr data-det-id="${detection.id}" tabindex="0">
          <td><span class="sev ${esc('sev-' + detection.severity)}">${esc(detection.severity)}</span></td>
          <td class="rule-cell">${esc(detection.rule_name)}</td>
          <td class="host-cell">${esc(detection.hostname)}</td>
          <td class="tech-cell">${esc(detection.technique_id || '—')}</td>
          <td><time>${esc(fmtTime(detection.detected_at_utc))}</time></td>
          <td class="row-arrow">›</td>
        </tr>`).join('');
    }

    function openDetection(id) {
      const detection = detections.find((item) => String(item.id) === String(id));
      if (!detection) return;
      const evidence = detection.evidence && Object.keys(detection.evidence).length ? JSON.stringify(detection.evidence, null, 2) : 'No raw evidence stored for this finding.';
      const techniquePath = String(detection.technique_id || '').replace('.', '/');
      $('#det-dialog-body').innerHTML = `
        <div class="detail-banner">
          <span class="sev ${esc('sev-' + detection.severity)}">${esc(detection.severity)}</span>
          <div><h3>${esc(detection.rule_name)}</h3><p>${esc(detection.hostname)} · ${esc(detection.technique_id || 'unmapped')} · ${esc(fmtTime(detection.detected_at_utc))}</p></div>
        </div>
        <div class="detail-grid">
          <div><span>Host</span><strong>${esc(detection.hostname)}</strong></div>
          <div><span>Technique</span><strong>${esc(detection.technique_name || '—')}</strong></div>
          <div><span>Hits</span><strong>${esc(detection.hit_count)}</strong></div>
          <div><span>Rule type</span><strong>${esc(detection.rule_type)}</strong></div>
          <div><span>Collection</span><strong>${esc(detection.collection_id || '—')}</strong></div>
          <div><span>Detected (UTC)</span><strong>${esc(fmtTime(detection.detected_at_utc))}</strong></div>
        </div>
        <div class="detail-section">
          <h4>ATT&CK tactics</h4>
          <div class="tactic-chips">${(detection.tactics || []).length ? detection.tactics.map((tactic) => `<span>${esc(tacticLabel(tactic.short || tactic.name))}</span>`).join('') : '<span>Not mapped</span>'}</div>
        </div>
        <div class="detail-section">
          <h4>Evidence</h4>
          <pre class="evidence-block">${esc(evidence)}</pre>
          ${detection.technique_id ? `<a class="technique-link" href="https://attack.mitre.org/techniques/${esc(techniquePath)}/" target="_blank" rel="noopener">Open ${esc(detection.technique_id)} on MITRE ATT&amp;CK ${svg('external')}</a>` : ''}
        </div>`;
      const dialog = $('#det-dialog');
      if (!dialog.open) dialog.showModal();
    }

    function renderChain() {
      const chain = data.chains?.[state.chainHost] || [];
      const host = hostById[state.chainHost];
      if (!host) {
        $('#ator-chain').innerHTML = '';
        return;
      }
      if (!chain.length) {
        $('#ator-chain').innerHTML = `<div class="panel" style="flex:1"><p class="table-hint">No ATT&amp;CK techniques were mapped for this endpoint.</p></div>`;
        $('#chain-detail').innerHTML = '<p class="table-hint">No chain to display.</p>';
        return;
      }
      $('#ator-chain').innerHTML = chain.map((stage, index) => `
        <div class="chain-stage">
          <span class="stage-order">${String(index + 1).padStart(2, '0')} · ${esc(stage.display || tacticLabel(stage.tactic))}</span>
          <h4>${esc(tacticLabel(stage.tactic))}</h4>
          <div class="tech-chips">
            ${stage.techniques.map((technique) => `<button class="tech-chip" type="button" data-tech-id="${esc(technique.id)}" data-tech-name="${esc(technique.name)}" data-tech-tactic="${esc(stage.tactic)}" data-tech-hits="${esc(technique.hits)}">${esc(technique.id)} · ${esc(technique.name)}</button>`).join('')}
          </div>
        </div>`).join('');
      const first = chain[0]?.techniques?.[0];
      if (first) showTechnique(first, chain[0].tactic, chain[0]);
    }

    function showTechnique(technique, tactic, stage) {
      $$('#ator-chain .tech-chip').forEach((chip) => chip.classList.toggle('is-active', chip.dataset.techId === technique.id));
      const related = detections.filter((detection) => detection.technique_id === technique.id && String(detection.host_id) === String(state.chainHost));
      $('#chain-detail').innerHTML = `
        <h4>${esc(technique.id)} · ${esc(technique.name)}</h4>
        <p><span class="technique-id">${esc(tacticLabel(tactic))}</span> — observed ${esc(technique.hits)} time${Number(technique.hits) === 1 ? '' : 's'} on ${esc(hostById[state.chainHost]?.hostname || 'endpoint')}.</p>
        ${related.length ? `<ul>${related.map((detection) => `<li>${esc(detection.rule_name)} · ${esc(fmtTime(detection.detected_at_utc))}</li>`).join('')}</ul>` : '<ul><li>No individual finding references this technique.</li></ul>'}`;
    }

    function renderHosts() {
      const endpointById = Object.fromEntries((data.endpoints || []).map((host) => [String(host.id), host]));
      $('#ator-hosts').innerHTML = data.hosts.map((host) => {
        const endpoint = endpointById[String(host.id)] || {};
        const icon = host.os_type === 'windows' ? 'windows' : host.os_type === 'docker_host' ? 'docker' : 'linux';
        return `
          <article class="host-card">
            <div class="host-top">
              <span class="os-icon">${svg(icon)}</span>
              <div><h4>${esc(host.hostname)}</h4><span class="host-os">${esc(host.os_type.replace('_', ' '))}</span></div>
            </div>
            <div class="host-stats">
              <div><span>critical</span><b>${esc(endpoint.critical ?? 0)}</b></div>
              <div><span>high</span><b>${esc(endpoint.high ?? 0)}</b></div>
              <div><span>total</span><b>${esc(endpoint.detection_total ?? host.detection_count ?? 0)}</b></div>
            </div>
            <div class="host-foot">
              <time>${esc(fmtDay(host.last_seen_utc))}</time>
              <button class="host-investigate" type="button" data-host-investigate="${host.id}">Investigate →</button>
            </div>
          </article>`;
      }).join('');
    }

    function activateTab(name) {
      $$('[data-ator-tab]').forEach((tab) => {
        const active = tab.dataset.atorTab === name;
        tab.classList.toggle('is-active', active);
        tab.setAttribute('aria-selected', String(active));
      });
      $$('[data-ator-view]').forEach((view) => view.classList.toggle('is-active', view.dataset.atorView === name));
      if (name === 'report' && !state.reportLoaded) {
        const frame = $('#report-frame');
        if (frame?.dataset.src) {
          frame.src = frame.dataset.src;
          state.reportLoaded = true;
        }
      }
    }

    $$('[data-ator-tab]').forEach((tab) => tab.addEventListener('click', () => activateTab(tab.dataset.atorTab)));

    $('#det-search').addEventListener('input', (event) => { state.q = event.target.value; renderDetections(); });
    $('#det-severity').addEventListener('change', (event) => { state.severity = event.target.value; renderDetections(); });
    $('#det-host').addEventListener('change', (event) => { state.host = event.target.value; renderDetections(); });
    $('#det-reset').addEventListener('click', () => {
      state.q = ''; state.severity = ''; state.host = '';
      $('#det-search').value = ''; $('#det-severity').value = ''; $('#det-host').value = '';
      renderDetections();
    });
    $('#chain-host').addEventListener('change', (event) => { state.chainHost = event.target.value; renderChain(); });

    $('#ator-dets').addEventListener('click', (event) => {
      const row = event.target.closest('[data-det-id]');
      if (row) openDetection(row.dataset.detId);
    });
    $('#ator-dets').addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const row = event.target.closest('[data-det-id]');
      if (row) { event.preventDefault(); openDetection(row.dataset.detId); }
    });
    $('#ator-recent').addEventListener('click', (event) => {
      const row = event.target.closest('[data-det-id]');
      if (row) openDetection(row.dataset.detId);
    });
    $('#ator-chain').addEventListener('click', (event) => {
      const chip = event.target.closest('[data-tech-id]');
      if (!chip) return;
      const chain = data.chains?.[state.chainHost] || [];
      const stage = chain.find((item) => item.tactic === chip.dataset.techTactic);
      const technique = stage?.techniques.find((item) => item.id === chip.dataset.techId) || { id: chip.dataset.techId, name: chip.dataset.techName, hits: chip.dataset.techHits };
      if (stage) showTechnique(technique, stage.tactic, stage);
    });
    $$('[data-goto-detections]').forEach((button) => button.addEventListener('click', () => activateTab('detections')));
    $('#ator-hosts').addEventListener('click', (event) => {
      const button = event.target.closest('[data-host-investigate]');
      if (!button) return;
      state.host = button.dataset.hostInvestigate;
      state.severity = '';
      state.q = '';
      $('#det-host').value = state.host;
      $('#det-severity').value = '';
      $('#det-search').value = '';
      renderDetections();
      activateTab('detections');
    });

    const reportHost = data.hosts.find((host) => String(host.id) === '1') || data.hosts[0];
    $('#report-verdict').textContent = risk.verdict || '—';
    const reportFindings = Object.values(risk.counts || {}).reduce((sum, value) => sum + Number(value || 0), 0);
    $('#report-count').textContent = `${reportFindings} findings`;
    $('#report-stages').textContent = `${risk.attack_stages_observed ?? 0} stages`;
    $('#report-date').textContent = fmtDay(data.report_generated_at);
    if (reportHost) $('#report-count').title = reportHost.hostname;

    renderDetections();
    renderChain();
    renderHosts();
  }

  const MED_KEY = 'youssef-portfolio-meditrack-v1';

  function localDateISO(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  async function initMediTrack() {
    const shell = $('#meditrack-demo');
    if (!shell) return;
    let data;
    try {
      const response = await fetch('assets/data/meditrack.json');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      data = await response.json();
    } catch (error) {
      $('#med-kpis').innerHTML = '<div class="kpi" style="grid-column:1/-1"><div class="kpi-label">Data unavailable</div><div class="kpi-value"><strong>—</strong></div></div>';
      return;
    }

    const now = new Date();
    const monday = new Date(now);
    const weekday = (now.getDay() + 6) % 7;
    monday.setDate(now.getDate() - weekday);
    monday.setHours(0, 0, 0, 0);
    const weekDates = Array.from({ length: 7 }, (_, index) => {
      const date = new Date(monday);
      date.setDate(monday.getDate() + index);
      return date;
    });
    const todayISO = localDateISO(now);

    let state;
    try {
      const saved = JSON.parse(localStorage.getItem(MED_KEY) || 'null');
      if (saved && Array.isArray(saved.medications) && saved.taken) state = saved;
    } catch (error) { /* fallback below */ }

    if (!state) {
      const medications = data.medications.map((medication) => ({ ...medication }));
      const taken = {};
      medications.forEach((medication, medIndex) => {
        weekDates.forEach((date) => {
          if (localDateISO(date) >= todayISO) return;
          medication.times.forEach((time, timeIndex) => {
            if ((medIndex * 3 + date.getDay() + timeIndex) % 5 !== 0) {
              taken[`${medication.id}|${localDateISO(date)}|${time}`] = true;
            }
          });
        });
      });
      state = { medications, taken, version: 1 };
    }

    const save = () => {
      try { localStorage.setItem(MED_KEY, JSON.stringify(state)); } catch (error) { /* in-memory only */ }
    };

    const doseKey = (medicationId, dateISO, time) => `${medicationId}|${dateISO}|${time}`;
    const isTaken = (medicationId, dateISO, time) => Boolean(state.taken[doseKey(medicationId, dateISO, time)]);
    const medDoses = (medication, dateISO) => medication.times.map((time) => isTaken(medication.id, dateISO, time));
    const allDosesTaken = (medication, dateISO) => medDoses(medication, dateISO).every(Boolean);

    function weeklyStats() {
      const nowTime = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      let total = 0;
      let done = 0;
      state.medications.forEach((medication) => {
        weekDates.forEach((date) => {
          const dateISO = localDateISO(date);
          if (dateISO > todayISO) return;
          medication.times.forEach((time) => {
            if (dateISO === todayISO && time > nowTime) return;
            total += 1;
            if (isTaken(medication.id, dateISO, time)) done += 1;
          });
        });
      });
      return { total, done, percent: total ? Math.round((done / total) * 100) : 0 };
    }

    function renderKpis() {
      const stats = weeklyStats();
      const lowStock = state.medications.filter((medication) => Number(medication.stock) <= Number(medication.threshold));
      const todayDoses = state.medications.reduce((sum, medication) => sum + medication.times.length, 0);
      const todayTaken = state.medications.reduce((sum, medication) => sum + medDoses(medication, todayISO).filter(Boolean).length, 0);
      $('#med-kpis').innerHTML = `
        <div class="kpi"><div class="kpi-label">Active medications</div><div class="kpi-value"><strong>${state.medications.length}</strong><span>in inventory</span></div><div class="kpi-hint">demo patient</div></div>
        <div class="kpi"><div class="kpi-label">Low stock</div><div class="kpi-value"><strong class="${lowStock.length ? 'warn' : 'ok'}">${lowStock.length}</strong><span>need refill</span></div><div class="kpi-hint">stock ≤ threshold</div></div>
        <div class="kpi"><div class="kpi-label">Today's doses</div><div class="kpi-value"><strong>${todayTaken}/${todayDoses}</strong><span>taken</span></div><div class="kpi-hint">${todayISO}</div></div>
        <div class="kpi"><div class="kpi-label">Weekly adherence</div><div class="kpi-value"><strong class="${stats.percent >= 80 ? 'ok' : 'warn'}">${stats.percent}%</strong><span>doses taken</span></div><div class="kpi-hint">${stats.done}/${stats.total} due so far</div></div>`;
    }

    function renderInventory() {
      const query = $('#med-search').value.trim().toLowerCase();
      const lowOnly = $('#med-low-only').checked;
      const items = state.medications.filter((medication) => {
        if (lowOnly && Number(medication.stock) > Number(medication.threshold)) return false;
        return !query || `${medication.name} ${medication.strength} ${medication.form}`.toLowerCase().includes(query);
      });
      $('#med-count').textContent = `${items.length} medication${items.length === 1 ? '' : 's'}`;
      if (!items.length) {
        $('#med-table').innerHTML = '<tr><td colspan="5"><p class="table-hint" style="padding:14px 0">No medications match this view.</p></td></tr>';
        return;
      }
      $('#med-table').innerHTML = items.map((medication) => {
        const low = Number(medication.stock) <= Number(medication.threshold);
        const ratio = Math.min(100, Math.round((Number(medication.stock) / Math.max(1, Number(medication.threshold) * 2)) * 100));
        return `<tr>
          <td><div class="med-name"><span class="med-dot" style="background:${esc(medication.color)}"></span><div><strong>${esc(medication.name)}</strong><small>${esc(medication.strength)} · ${esc(medication.form)}</small></div></div></td>
          <td class="schedule-cell">${esc(medication.schedule)}<br><small style="color:var(--faint);font-size:8px">${esc(medication.note || '')}</small></td>
          <td class="stock-cell"><div class="stock-bar"><div class="stock-track"><div class="stock-fill ${low ? 'low' : ''}" style="width:${ratio}%"></div></div><span class="stock-num">${esc(medication.stock)}</span></div></td>
          <td><span class="status-chip ${low ? 'status-low' : 'status-ok'}">${low ? 'low stock' : 'in stock'}</span></td>
          <td><button class="icon-btn" type="button" data-remove-med="${esc(medication.id)}" aria-label="Remove ${esc(medication.name)}">${svg('close')}</button></td>
        </tr>`;
      }).join('');
    }

    function renderWeek() {
      $('#med-week-range').textContent = `${weekDates[0].toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })} – ${weekDates[6].toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}`;
      const stats = weeklyStats();
      $('#med-adherence').textContent = `${stats.percent}%`;
      const header = `<thead><tr><th>Medication</th>${weekDates.map((date) => `<th class="${localDateISO(date) === todayISO ? 'is-today' : ''}">${date.toLocaleDateString('en-GB', { weekday: 'short' })}<br>${String(date.getDate()).padStart(2, '0')}</th>`).join('')}</tr></thead>`;
      const rows = state.medications.map((medication) => `
        <tr>
          <td>${esc(medication.name)}<small>${esc(medication.schedule)}</small></td>
          ${weekDates.map((date) => {
            const dateISO = localDateISO(date);
            const doses = medDoses(medication, dateISO);
            const takenCount = doses.filter(Boolean).length;
            const complete = takenCount === doses.length;
            const partial = takenCount > 0 && !complete;
            return `<td><button class="dose-cell ${complete ? 'complete' : partial ? 'partial' : ''} ${dateISO === todayISO ? 'is-today' : ''}" type="button" data-dose-med="${esc(medication.id)}" data-dose-date="${dateISO}" aria-label="${esc(medication.name)} on ${dateISO}: ${takenCount} of ${doses.length} taken">${doses.map((taken) => `<span class="dose-dot ${taken ? 'taken' : ''}"></span>`).join('')}<span class="dose-count">${takenCount}/${doses.length}</span></button></td>`;
          }).join('')}
        </tr>`).join('');
      $('#med-week').innerHTML = header + `<tbody>${rows}</tbody>`;
    }

    function renderInteractionOptions() {
      const options = state.medications.map((medication) => `<option value="${esc(medication.name)}">${esc(medication.name)}</option>`).join('');
      const a = $('#int-a');
      const b = $('#int-b');
      const currentA = a.value;
      const currentB = b.value;
      a.innerHTML = options;
      b.innerHTML = options;
      if (state.medications.some((medication) => medication.name === currentA)) a.value = currentA;
      if (state.medications.some((medication) => medication.name === currentB)) b.value = currentB;
      if (!b.value && state.medications.length > 1) b.selectedIndex = 1;
    }

    function findInteraction(nameA, nameB) {
      const pair = [nameA.toLowerCase(), nameB.toLowerCase()].sort();
      return data.interactions.find((interaction) => [interaction.a.toLowerCase(), interaction.b.toLowerCase()].sort().join('|') === pair.join('|'));
    }

    function renderInteractions() {
      renderInteractionOptions();
      const existing = data.interactions.filter((interaction) => state.medications.some((medication) => medication.name === interaction.a) && state.medications.some((medication) => medication.name === interaction.b));
      $('#med-interactions').innerHTML = existing.length ? existing.map((interaction) => `
        <article class="interaction-card">
          <div class="pair">${esc(interaction.a)}<b>+</b>${esc(interaction.b)}</div>
          <div>
            <h4><span class="sev ${interaction.severity === 'major' ? 'sev-critical' : 'sev-high'}">${esc(interaction.severity)}</span></h4>
            <p>${esc(interaction.effect)}</p>
            <p class="advice"><strong style="color:var(--muted)">Action:</strong> ${esc(interaction.action)}</p>
          </div>
        </article>`).join('') : '<p class="table-hint">No interactions in the sample dataset for the current medications.</p>';
    }

    function checkInteraction() {
      const a = $('#int-a').value;
      const b = $('#int-b').value;
      const result = $('#int-result');
      if (!a || !b) {
        result.className = 'interaction-result';
        result.innerHTML = '<p>Select two medications first.</p>';
        return;
      }
      if (a === b) {
        result.className = 'interaction-result moderate';
        result.innerHTML = '<p><strong>Choose two different medications.</strong>Comparing a medication with itself is not useful.</p>';
        return;
      }
      const interaction = findInteraction(a, b);
      if (!interaction) {
        result.className = 'interaction-result safe';
        result.innerHTML = `<p><span class="risk-word">no match</span><strong>${esc(a)} + ${esc(b)}</strong>No interaction is listed in this demo dataset. Always confirm with a pharmacist or prescriber.</p>`;
        return;
      }
      result.className = `interaction-result ${interaction.severity}`;
      result.innerHTML = `<p><span class="risk-word">${esc(interaction.severity)}</span><strong>${esc(interaction.a)} + ${esc(interaction.b)}</strong>${esc(interaction.effect)}<br><span style="color:var(--muted)">${esc(interaction.action)}</span></p>`;
    }

    function renderAll() {
      renderKpis();
      renderInventory();
      renderWeek();
      renderInteractions();
      renderInteractionOptions();
    }

    function toggleDay(medicationId, dateISO) {
      const medication = state.medications.find((item) => item.id === medicationId);
      if (!medication) return;
      const allTaken = allDosesTaken(medication, dateISO);
      medication.times.forEach((time) => {
        if (allTaken) delete state.taken[doseKey(medicationId, dateISO, time)];
        else state.taken[doseKey(medicationId, dateISO, time)] = true;
      });
      save();
      renderKpis();
      renderWeek();
    }

    function removeMedication(id) {
      const medication = state.medications.find((item) => item.id === id);
      if (!medication) return;
      if (!window.confirm(`Remove ${medication.name} from the demo inventory?`)) return;
      state.medications = state.medications.filter((item) => item.id !== id);
      Object.keys(state.taken).forEach((key) => { if (key.startsWith(`${id}|`)) delete state.taken[key]; });
      save();
      renderAll();
      toast(`${medication.name} removed from the demo`);
    }

    $('#med-search').addEventListener('input', renderInventory);
    $('#med-low-only').addEventListener('change', renderInventory);
    $('#med-table').addEventListener('click', (event) => {
      const button = event.target.closest('[data-remove-med]');
      if (button) removeMedication(button.dataset.removeMed);
    });
    $('#med-week').addEventListener('click', (event) => {
      const cell = event.target.closest('[data-dose-med]');
      if (cell) toggleDay(cell.dataset.doseMed, cell.dataset.doseDate);
    });
    $('#int-check').addEventListener('click', checkInteraction);

    $$('[data-med-tab]').forEach((tab) => tab.addEventListener('click', () => {
      $$('[data-med-tab]').forEach((item) => {
        item.classList.toggle('is-active', item === tab);
        item.setAttribute('aria-selected', String(item === tab));
      });
      $$('[data-med-view]').forEach((view) => view.classList.toggle('is-active', view.dataset.medView === tab.dataset.medTab));
    }));

    const dialog = $('#med-dialog');
    $('#med-add-open').addEventListener('click', () => {
      $('#med-form').reset();
      $('#med-form').elements.stock.value = 30;
      $('#med-form').elements.threshold.value = 10;
      dialog.showModal();
      setTimeout(() => $('#med-form').elements.name.focus(), 60);
    });

    $('#med-form').addEventListener('submit', (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const formData = new FormData(form);
      const times = String(formData.get('times') || '').split(',').map((time) => time.trim()).filter(Boolean);
      const palette = ['#57d9ff', '#a78bfa', '#3ddc97', '#ffb454', '#ff7a90', '#f4d35e'];
      const medication = {
        id: `med-${Date.now()}`,
        name: String(formData.get('name')).trim(),
        strength: String(formData.get('strength')).trim(),
        form: String(formData.get('form')).trim(),
        schedule: String(formData.get('schedule')).trim(),
        times: times.length ? times : ['09:00'],
        stock: Number(formData.get('stock')),
        threshold: Number(formData.get('threshold')),
        color: palette[state.medications.length % palette.length],
        note: 'Added in the browser demo'
      };
      state.medications.push(medication);
      save();
      dialog.close();
      renderAll();
      toast(`${medication.name} added to the demo`);
    });

    $('#med-reset').addEventListener('click', () => {
      if (!window.confirm('Reset the demo to its original sample data?')) return;
      try { localStorage.removeItem(MED_KEY); } catch (error) { /* ignore */ }
      window.location.reload();
    });

    renderAll();
  }

  function initPipeline() {
    const stages = $$('#pipe-stages .pipe-stage');
    if (!stages.length) return;
    const runButton = $('#pipe-run');
    const failToggle = $('#pipe-fail');
    const log = $('#pipe-log');
    const status = $('#pipe-status');
    const duration = $('#pipe-duration');
    const tests = $('#pipe-tests');
    let running = false;

    const stageScripts = {
      checkout: [
        ['$ git fetch --prune origin', 'cmd'],
        ['From github.com:youssefbouaouina/devopsNIDS', 'muted'],
        ['HEAD is now at 7c1a9e2 feat: add alert correlation endpoint', 'ok']
      ],
      build: [
        ['$ mvn -B -DskipTests clean package', 'cmd'],
        ['[INFO] Compiling 24 source files to target/classes', 'muted'],
        ['[INFO] BUILD SUCCESS', 'ok']
      ],
      test: [
        ['$ mvn -B test', 'cmd'],
        ['[INFO] Tests run: 42, Failures: 0, Errors: 0, Skipped: 1', 'ok'],
        ['[INFO] Surefire report written to target/surefire-reports', 'muted']
      ],
      quality: [
        ['$ sonar-scanner -Dsonar.projectKey=devopsnids', 'cmd'],
        ['[INFO] Quality Gate: PASSED (0 vulnerabilities, 0 bugs)', 'ok'],
        ['[INFO] Coverage on new code: 84.2%', 'ok']
      ],
      package: [
        ['$ docker build -t devopsnids:184 .', 'cmd'],
        ['[INFO] Successfully tagged devopsnids:184', 'ok'],
        ['$ docker push registry.local/devopsnids:184', 'cmd']
      ],
      deploy: [
        ['$ kubectl apply -f k8s/', 'cmd'],
        ['deployment.apps/devopsnids configured', 'muted'],
        ['$ kubectl rollout status deployment/devopsnids', 'cmd'],
        ['deployment "devopsnids" successfully rolled out', 'ok']
      ]
    };

    const logLine = (text, kind = '') => {
      const line = document.createElement('div');
      if (kind) line.className = `log-${kind}`;
      line.textContent = text;
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    };

    const setStage = (stage, state) => {
      stage.classList.remove('running', 'success', 'failed');
      if (state) stage.classList.add(state);
      const label = $('.stage-state', stage);
      if (label) label.textContent = state === 'success' ? 'passed' : state === 'failed' ? 'failed' : state === 'running' ? 'running' : 'queued';
    };

    const reset = () => {
      stages.forEach((stage) => setStage(stage, ''));
      log.innerHTML = '<span class="log-muted">$ waiting for a build…</span>';
      status.textContent = 'idle';
      duration.textContent = '—';
      tests.textContent = '42';
    };

    runButton.addEventListener('click', async () => {
      if (running) return;
      running = true;
      runButton.disabled = true;
      runButton.innerHTML = '<span class="live-dot"></span>Running…';
      reset();
      status.textContent = 'running';
      log.innerHTML = '';
      logLine('Started by user youssefbouaouina', 'muted');
      logLine('Running on Jenkins agent linux-x64-04', 'muted');
      const shouldFail = failToggle.checked;
      const pause = reduceMotion ? 60 : 520;

      for (const stage of stages) {
        const name = stage.dataset.stage;
        setStage(stage, 'running');
        const script = stageScripts[name] || [];
        for (const [text, kind] of script) {
          logLine(text, kind);
          await sleep(pause * 0.55);
        }
        if (name === 'test' && shouldFail) {
          logLine('[ERROR] Tests run: 42, Failures: 1, Errors: 0, Skipped: 1', 'err');
          logLine('[ERROR] Failed: AlertControllerTest.shouldRejectInvalidPayload', 'err');
          logLine('BUILD FAILURE', 'err');
          setStage(stage, 'failed');
          status.textContent = 'failed';
          duration.textContent = '1m 08s';
          tests.textContent = '41 passed · 1 failed';
          logLine('Finished: FAILURE', 'err');
          running = false;
          runButton.disabled = false;
          runButton.innerHTML = `${svg('play')}Run pipeline`;
          return;
        }
        await sleep(pause * 0.35);
        setStage(stage, 'success');
      }

      duration.textContent = '2m 14s';
      status.textContent = 'success';
      logLine('Finished: SUCCESS', 'ok');
      logLine('Archived artifacts: target/*.jar, target/surefire-reports/*', 'muted');
      running = false;
      runButton.disabled = false;
      runButton.innerHTML = `${svg('play')}Run again`;
    });
  }

  revealOnScroll();
  initHeader();
  initDialogs();
  initAtor();
  initMediTrack();
  initPipeline();
})();
