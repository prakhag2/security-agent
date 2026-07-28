// ===== Project State =====
const currentProject = 'juiceshop';

// ===== Tab Switching =====
function switchTab(name) {
  document.querySelectorAll('.tab-bar button').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-btn-' + name).classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');

  if (name === 'complexity' && !graphLoaded) loadGraph();
  if (name === 'flow' && !flowLoaded) loadFlow();
  if (name === 'scan' && !scanListLoaded) loadScanList();
}

// ===== Flow View Toggle (Tree vs Neo4j) =====
let flowCurrentView = 'tree';

function setFlowView(view) {
  if (view === 'graph') {
    const sel = document.getElementById('flow-select');
    const testName = sel.value;
    openNeo4jBrowser(testName);
    return;
  }
  flowCurrentView = 'tree';
  document.getElementById('flow-view-tree').classList.add('active');
  document.getElementById('flow-view-graph').classList.remove('active');
  document.getElementById('flow-content').style.display = '';
}

let _currentScanTest = '';
let _labelTargetsPromise = null;

function openNeo4jBrowser(testName) {
  if (testName) {
    fetch(`/api/juiceshop/neo4j-load?test=${encodeURIComponent(testName)}`).catch(() => {});
  }
  const query = testName
    ? `MATCH (n:JuiceShop {test:'${testName}'})-[r]->(m) RETURN *`
    : 'MATCH (n:JuiceShop)-[r]->(m) RETURN * LIMIT 100';
  const dbms = encodeURIComponent(`bolt+s://${window.location.host}:443`);
  const url = `/browser/?dbms=${dbms}&cmd=edit&arg=${encodeURIComponent(query)}`;
  window.open(url, '_blank');
}


async function openAttackTargetsInNeo4j() {
  const btns = document.querySelectorAll('.neo4j-targets-btn');
  btns.forEach(b => { b.disabled = true; b.dataset.origText = b.textContent; b.textContent = 'Loading Neo4j Browser...'; });
  try {
    const test = _currentScanTest;
    if (_labelTargetsPromise) {
      try { await _labelTargetsPromise; } catch(e) {}
    }
    const query = test
      ? `MATCH (a {test:'${test}'})-[r]->(b {test:'${test}'}) WHERE type(r) STARTS WITH 'ATTACK_PATH' RETURN a, r, b`
      : `MATCH (a:Targeted)-[r]->(b) WHERE type(r) STARTS WITH 'ATTACK_PATH' RETURN a, r, b LIMIT 200`;
    const dbms = encodeURIComponent(`bolt+s://${window.location.host}:443`);
    const url = `/browser/?dbms=${dbms}&cmd=edit&arg=${encodeURIComponent(query)}`;
    window.open(url, '_blank');
  } finally {
    setTimeout(() => { btns.forEach(b => { b.disabled = false; b.textContent = b.dataset.origText || 'Examine Identified Attack Targets'; }); }, 2000);
  }
}


// ===== API Helpers =====
async function api(path) {
  const resp = await fetch(path);
  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

// ===== Tab 1: Complexity Graph =====
let graphLoaded = false;

function categoryColor(id) {
  return juiceshopColor(id);
}

function juiceshopColor(id) {
  const lower = id.toLowerCase();
  if (lower.includes('login') || lower.includes('2fa') || lower.includes('verify')) return '#f85149';
  if (lower.includes('insecurity') || lower.includes('security')) return '#f0883e';
  if (lower.includes('utils')) return '#d2a8ff';
  if (lower.includes('challenge') || lower.includes('accuracy') || lower.includes('anticheat')) return '#e3b341';
  if (lower.includes('basket') || lower.includes('order') || lower.includes('payment') || lower.includes('wallet')) return '#7ee787';
  if (lower.includes('user') || lower.includes('profile') || lower.includes('address')) return '#58a6ff';
  if (lower.includes('file') || lower.includes('upload') || lower.includes('video')) return '#a5d6ff';
  if (lower.includes('search') || lower.includes('product') || lower.includes('memory')) return '#79c0ff';
  if (lower.includes('chat') || lower.includes('complaint') || lower.includes('feedback')) return '#56d364';
  if (lower.startsWith('routes/')) return '#ff7b72';
  if (lower.startsWith('lib/')) return '#d2a8ff';
  return '#6e7681';
}

async function loadGraph() {
  graphLoaded = true;
  try {
    const endpoint = '/api/juiceshop/graph';
    const data = await api(endpoint);
    renderGraph(data);
  } catch (e) {
    document.getElementById('graph-loading').textContent = 'Failed to load graph: ' + e.message;
  }
}

function renderGraph(data) {
  const container = document.getElementById('graph-container');
  const loading = document.getElementById('graph-loading');
  const statsEl = document.getElementById('graph-stats');
  const tooltip = document.getElementById('graph-tooltip');
  loading.style.display = 'none';
  statsEl.style.display = 'block';
  statsEl.innerHTML = `Packages: <span>${data.nodes.length}</span> | Edges: <span>${data.edges.length}</span> | Functions: <span>${data.total_funcs}</span>`;

  const width = container.clientWidth;
  const height = container.clientHeight;

  const svg = d3.select(container).append('svg')
    .attr('width', width)
    .attr('height', height);

  const g = svg.append('g');

  svg.call(d3.zoom()
    .scaleExtent([0.2, 5])
    .on('zoom', (event) => g.attr('transform', event.transform)));

  const maxFuncs = d3.max(data.nodes, d => d.funcs) || 1;
  const rScale = d3.scaleSqrt().domain([0, maxFuncs]).range([4, 28]);
  const maxWeight = d3.max(data.edges, d => d.weight) || 1;
  const wScale = d3.scaleLinear().domain([1, maxWeight]).range([0.5, 4]);

  const sim = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.edges).id(d => d.id).distance(100).strength(0.3))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => rScale(d.funcs) + 4));

  const link = g.append('g')
    .selectAll('line')
    .data(data.edges)
    .join('line')
    .attr('stroke', '#30363d')
    .attr('stroke-width', d => wScale(d.weight))
    .attr('stroke-opacity', 0.6);

  const node = g.append('g')
    .selectAll('circle')
    .data(data.nodes)
    .join('circle')
    .attr('r', d => rScale(d.funcs))
    .attr('fill', d => categoryColor(d.id))
    .attr('fill-opacity', 0.8)
    .attr('stroke', d => categoryColor(d.id))
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.4)
    .call(d3.drag()
      .on('start', (event, d) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on('end', (event, d) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

  const labelThreshold = 5;
  const labels = g.append('g')
    .selectAll('text')
    .data(data.nodes.filter(d => d.funcs > labelThreshold))
    .join('text')
    .text(d => d.id.split('/').pop())
    .attr('font-size', 9)
    .attr('fill', '#8b949e')
    .attr('text-anchor', 'middle')
    .attr('dy', d => rScale(d.funcs) + 12)
    .style('pointer-events', 'none');

  node.on('mouseover', (event, d) => {
    tooltip.style.display = 'block';
    tooltip.innerHTML = `<div class="tt-pkg">${d.id}</div><div class="tt-stat">${d.funcs} functions | ${d.files} files</div>`;
  })
  .on('mousemove', (event) => {
    tooltip.style.left = (event.offsetX + 14) + 'px';
    tooltip.style.top = (event.offsetY - 10) + 'px';
  })
  .on('mouseout', () => { tooltip.style.display = 'none'; });

  sim.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y);
    node
      .attr('cx', d => d.x)
      .attr('cy', d => d.y);
    labels
      .attr('x', d => d.x)
      .attr('y', d => d.y);
  });
}

// ===== Tab 2: Flow (Call Tree) =====
let flowLoaded = false;
let flowAllData = null;

async function loadFlow() {
  flowLoaded = true;
  const panel = document.getElementById('flow-content');
  const sel = document.getElementById('flow-select');

  try {
    const index = await api('/api/juiceshop/tests');
    flowAllData = {};
    const suites = {};
    for (const t of index) {
      if (!suites[t.suite]) suites[t.suite] = [];
      suites[t.suite].push(t);
    }
    for (const [suite, tests] of Object.entries(suites).sort()) {
      const group = document.createElement('optgroup');
      group.label = suite || 'Other';
      for (const t of tests) {
        const opt = document.createElement('option');
        opt.value = t.name;
        opt.textContent = t.test_slug.replace(/^\d+_/, '').replace(/_/g, ' ').substring(0, 60);
        group.appendChild(opt);
      }
      sel.appendChild(group);
    }
  } catch (e) {
    flowAllData = {};
  }
}

async function loadFlowTest(testName) {
  const panel = document.getElementById('flow-content');
  if (!testName) {
    panel.innerHTML = '<div class="replay-empty">Select a test to view its call tree</div>';
    return;
  }

  panel.innerHTML = '<div class="scan-loading-center"><div class="spinner"></div><div>Loading call tree...</div></div>';
  try {
    const data = await api('/api/juiceshop/flow?test=' + encodeURIComponent(testName));
    if (data.error) {
      panel.innerHTML = '<div class="replay-empty">' + escHtml(data.error) + '</div>';
    } else {
      renderFlowTree(panel, testName, data);
    }
  } catch (e) {
    panel.innerHTML = '<div class="replay-empty">Failed to load: ' + escHtml(e.message) + '</div>';
  }
}

function buildTree(flatNodes) {
  const root = { children: [], depth: -1 };
  const stack = [root];

  for (let i = 0; i < flatNodes.length; i++) {
    const treeNode = { ...flatNodes[i], _idx: i, children: [] };
    while (stack.length > 1 && stack[stack.length - 1].depth >= treeNode.depth) {
      stack.pop();
    }
    stack[stack.length - 1].children.push(treeNode);
    stack.push(treeNode);
  }
  return root.children;
}

function renderFlowTree(panel, testName, data) {
  // Only show nodes that were actually traced (ran=true)
  const allNodes = data.nodes;
  const tracedNodes = allNodes.filter(n => n.ran === true);
  const reqDescs = data.request_descriptions || {};

  let html = '<div class="flow-summary">';
  html += `<span class="flow-test-name">${testName}</span>`;
  html += `<span class="flow-metric"><span class="flow-num">${tracedNodes.length}</span> traced calls</span>`;
  html += `<span class="flow-metric">${data.trace_entries} trace entries</span>`;
  html += '</div>';

  // Request context
  if (Object.keys(reqDescs).length > 0) {
    html += '<div class="flow-requests">';
    for (const [req, desc] of Object.entries(reqDescs)) {
      html += `<span class="flow-req-badge">${req}: ${escHtml(desc)}</span>`;
    }
    html += '</div>';
  }

  const tree = buildTree(tracedNodes);
  html += '<div class="flow-tree-container"><div class="flow-tree">';
  for (const child of tree) {
    html += renderFlowNode(child, 0);
  }
  html += '</div><div class="flow-detail" id="flow-detail"><p class="flow-detail-empty">Click a node to see runtime details</p></div></div>';

  panel.innerHTML = html;

  // Attach handlers
  panel.querySelectorAll('.flow-toggle:not(.leaf)').forEach(toggle => {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const treeNode = toggle.closest('.flow-node');
      const children = treeNode.querySelector(':scope > .flow-children');
      if (children) {
        const collapsed = children.classList.toggle('collapsed');
        toggle.classList.toggle('expanded', !collapsed);
      }
    });
  });

  panel.querySelectorAll('.flow-row').forEach(el => {
    el.addEventListener('click', () => {
      panel.querySelectorAll('.flow-row').forEach(e => e.classList.remove('selected'));
      el.classList.add('selected');
      const idx = parseInt(el.dataset.idx);
      if (!isNaN(idx) && tracedNodes[idx]) showFlowDetail(tracedNodes[idx], reqDescs);
    });
  });
}

function renderFlowNode(node, depth) {
  const hasChildren = node.children && node.children.length > 0;
  const depthColors = ['#58a6ff', '#3fb950', '#d2a8ff', '#ffa657', '#ff7b72', '#79c0ff'];
  const depthColor = depthColors[Math.min(depth, 5)];
  const toggleClass = hasChildren ? 'expanded' : 'leaf';

  let label = (node.func || node.match_name || '').replace(/^[│├└─→\s]+/, '');

  let badgeHtml = '';
  if (node.call_count > 0) {
    badgeHtml = `<span class="flow-badge ran">&times;${node.call_count}</span>`;
  }
  if (node.invocations && node.invocations.length > 0) {
    const inv = node.invocations[0];
    if (inv.output) {
      let out = inv.output;
      if (out.length > 30) out = out.substring(0, 27) + '...';
      badgeHtml += ` <span class="flow-badge output">${escHtml(out)}</span>`;
    }
  }

  let html = `<div class="flow-node">`;
  html += `<div class="flow-row" data-idx="${node._idx}" style="border-left-color:${depthColor};">`;
  html += `<span class="flow-toggle ${toggleClass}"></span>`;
  html += `<span class="flow-label">${escHtml(label)}</span>`;
  html += badgeHtml;
  html += `</div>`;

  if (hasChildren) {
    html += `<div class="flow-children">`;
    for (const child of node.children) {
      html += renderFlowNode(child, depth + 1);
    }
    html += `</div>`;
  }

  html += `</div>`;
  return html;
}

function showFlowDetail(node, reqDescs) {
  const panel = document.getElementById('flow-detail');
  if (!node) { panel.innerHTML = ''; return; }

  let html = `<h3>${escHtml(node.func || node.match_name)}</h3>`;
  html += `<div class="flow-detail-status">&times;${node.call_count} call${node.call_count > 1 ? 's' : ''}</div>`;

  if (node.invocations && node.invocations.length > 0) {
    html += `<div class="flow-detail-section"><div class="flow-detail-label">Runtime Calls (${node.invocations.length})</div>`;
    for (let i = 0; i < node.invocations.length; i++) {
      const inv = node.invocations[i];
      const reqName = inv.request || '';
      const reqDesc = reqDescs[reqName] || '';
      const reqFull = reqName + (reqDesc ? ': ' + reqDesc : '');

      html += `<div class="flow-invocation">`;
      html += `<div class="flow-inv-header">Call #${i + 1} <span class="flow-inv-req">${escHtml(reqFull)}</span></div>`;

      if (inv.input && Object.keys(inv.input).length > 0) {
        html += `<div class="flow-detail-label">Input</div>`;
        html += `<pre>${escHtml(JSON.stringify(inv.input, null, 2))}</pre>`;
      }
      if (inv.output !== undefined && inv.output !== null) {
        html += `<div class="flow-detail-label">Output</div>`;
        html += `<pre class="output">${escHtml(String(inv.output))}</pre>`;
      }
      if (inv.exception) {
        html += `<div class="flow-detail-label" style="color:var(--red)">Exception</div>`;
        html += `<pre class="exception">${escHtml(inv.exception)}</pre>`;
      }
      html += `</div>`;
    }
    html += `</div>`;
  }

  panel.innerHTML = html;
}

// ===== Tab 3: Scan (Agentic Security Review) =====
let scanRunning = false;
let scanEventSource = null;
let scanListLoaded = false;
let scanSelectedTest = '';
let scanFindings = [];
let scanStreamText = '';
let scanMode = 'dynamic';

function setScanMode(mode) {
  scanMode = mode;
  document.getElementById('scan-mode-static').classList.toggle('active', mode === 'static');
  document.getElementById('scan-mode-dynamic').classList.toggle('active', mode === 'dynamic');
  document.getElementById('scan-content-dynamic').style.display = mode === 'dynamic' ? '' : 'none';
  document.getElementById('scan-content-static').style.display = mode === 'static' ? '' : 'none';
  document.querySelectorAll('.scan-dynamic-only').forEach(el => el.style.display = mode === 'dynamic' ? '' : 'none');
  if (mode === 'static') {
    loadStaticFindings();
  }
}

async function loadStaticFindings() {
  const content = document.getElementById('scan-content-static');
  content.innerHTML = '<div class="scan-loading-center"><div class="spinner"></div><div>Loading static analysis findings...</div></div>';
  setScanStatus('Loading...', 'running');
  try {
    const data = await api('/api/static-findings?project=juiceshop');
    if (data.error) {
      content.innerHTML = `<div class="scan-empty">${escHtml(data.error)}</div>`;
      setScanStatus('Error', 'error');
      return;
    }
    renderStaticFindings(data, content);
    setScanStatus(`${data.total_findings} findings`, 'done');
  } catch (e) {
    content.innerHTML = `<div class="scan-empty">Failed to load findings: ${escHtml(e.message)}</div>`;
    setScanStatus('Error', 'error');
  }
}

function renderStaticFindings(data, container) {
  const hasTrace = data.trace_entries && data.trace_entries > 0;
  const inTrace = hasTrace ? data.findings.filter(f => f.in_trace) : data.findings;
  const notInTrace = hasTrace ? data.findings.filter(f => !f.in_trace) : [];
  const dynamic = data.dynamic_findings || [];

  const critical = data.findings.filter(f => f.severity === 'Critical').length;
  const high = data.findings.filter(f => f.severity === 'High').length;
  const medium = data.findings.filter(f => f.severity === 'Medium').length;

  let html = `
    <div class="static-findings-layout">
      <div class="static-summary">
        <div class="summary-card">
          <div class="summary-number">${data.total_findings}</div>
          <div class="summary-label">Total Findings</div>
          <div class="summary-sub">${data.source}</div>
        </div>
        <div class="summary-card" style="border-left:3px solid var(--red)">
          <div class="summary-number">${critical}</div>
          <div class="summary-label">Critical</div>
        </div>
        <div class="summary-card" style="border-left:3px solid var(--orange)">
          <div class="summary-number">${high}</div>
          <div class="summary-label">High</div>
        </div>
        <div class="summary-card" style="border-left:3px solid var(--yellow,#e6a817)">
          <div class="summary-number">${medium}</div>
          <div class="summary-label">Medium</div>
        </div>
      </div>`;

  if (hasTrace) {
    html += `
      <div class="static-findings-section">
        <div class="section-header">Findings In Traced Code Paths <span class="count-badge">${inTrace.length}</span></div>
        ${inTrace.map(f => renderStaticFinding(f, true)).join('')}
      </div>`;
  } else {
    html += `
      <div class="static-findings-section">
        <div class="section-header">Security Findings <span class="count-badge">${data.findings.filter(f=>f.category==='Security').length}</span></div>
        ${data.findings.filter(f=>f.category==='Security').map(f => renderStaticFinding(f, true)).join('')}
      </div>
      <div class="static-findings-section">
        <div class="section-header">Non-Compliant Requirements <span class="count-badge">${data.findings.filter(f=>f.category!=='Security').length}</span></div>
        ${data.findings.filter(f=>f.category!=='Security').map(f => renderStaticFinding(f, true)).join('')}
      </div>`;
  }

  if (dynamic.length > 0) {
    html += `
      <div class="static-findings-section">
        <div class="section-header dynamic-header">Dynamic Tracer Findings <span class="count-badge dynamic">${dynamic.length}</span></div>
        ${dynamic.map((f, i) => renderDynamicFinding(f, i)).join('')}
      </div>`;
  }

  if (hasTrace && notInTrace.length > 0) {
    html += `
      <div class="static-findings-section collapsed-section">
        <div class="section-header dimmed-header" onclick="this.parentElement.classList.toggle('collapsed-section')">
          Not In Trace (${notInTrace.length}) <span class="expand-hint">click to expand</span>
        </div>
        ${notInTrace.map(f => renderStaticFinding(f, false)).join('')}
      </div>`;
  }

  html += `</div>`;
  container.innerHTML = html;
}

function renderStaticFinding(f, inTrace) {
  const sevClass = f.severity.toLowerCase();
  const catBadge = f.category === 'Security' ? 'cat-security' : 'cat-compliance';
  const overlapHtml = f.overlap_details.length > 0
    ? f.overlap_details.map(o => {
        if (o.match === 'direct') return `<span class="overlap-tag direct">${o.file}:${o.finding_lines.join(',')}</span>`;
        return `<span class="overlap-tag proximity">${o.file} (near traced lines)</span>`;
      }).join(' ')
    : '';

  return `
    <div class="static-finding-card ${inTrace ? '' : 'dimmed'}">
      <div class="sf-header">
        <span class="sf-severity ${sevClass}">${f.severity}</span>
        <span class="sf-category ${catBadge}">${f.category}</span>
        <span class="sf-id">${f.id}</span>
        <span class="sf-title">${escHtml(f.title)}</span>
      </div>
      <div class="sf-body">
        <div class="sf-desc">${escHtml(f.description)}</div>
        <div class="sf-locations">${f.locations.map(l => `<code>${l.file}:${l.lines[0]}${l.lines.length > 1 ? '-' + l.lines[l.lines.length-1] : ''}</code>`).join(' ')}</div>
        ${overlapHtml ? `<div class="sf-overlap">Trace overlap: ${overlapHtml}</div>` : ''}
      </div>
    </div>`;
}

function renderDynamicFinding(f, idx) {
  const title = f.title || f.vulnerability || f.name || ('Finding ' + (idx + 1));
  const desc = f.description || f.details || f.reasoning || '';
  const loc = f.location || f.file || '';
  const sev = f.severity || 'Medium';
  const sevClass = sev.toLowerCase();

  return `
    <div class="static-finding-card dynamic-card">
      <div class="sf-header">
        <span class="sf-severity ${sevClass}">${sev}</span>
        <span class="sf-category cat-dynamic">Dynamic</span>
        <span class="sf-id">V${idx + 1}</span>
        <span class="sf-title">${escHtml(title)}</span>
      </div>
      <div class="sf-body">
        <div class="sf-desc">${escHtml(desc)}</div>
        ${loc ? `<div class="sf-locations"><code>${escHtml(loc)}</code></div>` : ''}
      </div>
    </div>`;
}

function loadScanList() {
  if (scanListLoaded) return;
  scanListLoaded = true;
  const sel = document.getElementById('scan-select');

  api('/api/juiceshop/tests').then(index => {
    const suites = {};
    for (const t of index) {
      if (!suites[t.suite]) suites[t.suite] = [];
      suites[t.suite].push(t);
    }
    for (const [suite, tests] of Object.entries(suites).sort()) {
      const group = document.createElement('optgroup');
      group.label = suite || 'Other';
      for (const t of tests) {
        const opt = document.createElement('option');
        opt.value = t.name;
        opt.textContent = t.test_slug.replace(/^\d+_/, '').replace(/_/g, ' ').substring(0, 60);
        group.appendChild(opt);
      }
      sel.appendChild(group);
    }
  }).catch(() => {});
  checkSavedScans();
}

function checkSavedScans() {
  api('/api/scan-results?project=juiceshop').then(results => {
    const btn = document.getElementById('scan-load-btn');
    if (results && results.length > 0) {
      btn.style.display = '';
    } else {
      btn.style.display = 'none';
    }
  }).catch(() => {});
}

function scanTestChanged(val) {
  scanSelectedTest = val;
}

function setScanStatus(text, state) {
  document.getElementById('scan-status-text').textContent = text;
  const pulse = document.getElementById('scan-pulse');
  pulse.className = 'pulse' + (state === 'idle' ? ' idle' : state === 'done' ? ' done' : state === 'error' ? ' error' : '');
}


function endScanSSE() {
  scanRunning = false;
  if (scanEventSource) scanEventSource.close();
  scanEventSource = null;
  const btn = document.getElementById('scan-run-btn');
  if (btn) { btn.textContent = 'Run Vulnerability Scan'; btn.classList.remove('running'); }
  document.getElementById('scan-load-btn').style.display = '';
}

function parseFindingsFromStream(text) {
  const findings = [];
  const sections = text.split(/(?=##\s*(?:Finding|⚠️|✅|P\d|CONFIRMED|POTENTIAL)[\s\d]*[:—\-]?)/i);
  for (const section of sections) {
    if (!section.trim()) continue;
    const titleMatch = section.match(/##\s*(.+?)[\n\r]/);
    if (!titleMatch) continue;
    const rawTitle = titleMatch[1].trim();
    if (rawTitle.toLowerCase().startsWith('executive') || rawTitle.toLowerCase().startsWith('overview') ||
        rawTitle.toLowerCase().startsWith('summary') || rawTitle.toLowerCase().startsWith('test') ||
        rawTitle.toLowerCase().startsWith('request') || rawTitle.toLowerCase().startsWith('your') ||
        rawTitle.toLowerCase().startsWith('source') || rawTitle.toLowerCase().startsWith('trace') ||
        rawTitle.toLowerCase().startsWith('execution')) continue;

    const finding = { title: rawTitle, severity: 'info', location: '', body: section.substring(titleMatch[0].length).trim() };

    // Detect severity from content
    const sevMatch = section.match(/\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b/i);
    if (sevMatch) finding.severity = sevMatch[1].toLowerCase();
    // Also detect from title prefix
    if (rawTitle.includes('SECURE') || rawTitle.startsWith('✅')) finding.severity = 'secure';
    if (rawTitle.includes('MEDIUM') || rawTitle.startsWith('⚠️ MEDIUM')) finding.severity = 'medium';
    if (rawTitle.includes('HIGH')) finding.severity = 'high';
    if (rawTitle.includes('LOW')) finding.severity = 'low';

    const locMatch = section.match(/\*\*Location:?\*\*\s*(.+)/i) || section.match(/Location:\s*(.+)/i);
    if (locMatch) finding.location = locMatch[1].trim();

    findings.push(finding);
  }
  return findings;
}

function renderFindings(findings) {
  if (!findings || findings.length === 0) {
    return `<div class="scan-no-findings"><div class="check-icon">✓</div><div>No vulnerabilities found</div></div>`;
  }

  let html = `<div class="scan-findings-header"><span>Vulnerabilities</span><span class="count-badge vuln">${findings.length}</span></div>`;

  findings.forEach((f, idx) => {
    const categoryColors = {session_fixation:'#d29922',auth_bypass:'#f85149',privilege_escalation:'#f85149',input_validation:'#d29922',race_condition:'#a371f7',crypto:'#a371f7',state_confusion:'#d29922'};
    const categoryBadge = f.category
      ? `<span class="category-badge" style="border-color:${categoryColors[f.category]||'var(--border)'};color:${categoryColors[f.category]||'var(--text-dim)'}">${escHtml(f.category.replace(/_/g,' '))}</span>`
      : '';

    const location = f.file ? `<div class="finding-location">${escHtml(f.file)}:${escHtml(f.function || '')}</div>` : '';

    html += `<div class="finding-card" id="finding-card-${idx}">
      <div class="finding-card-header" onclick="toggleFinding(${idx})">
        <span class="expand-icon">▶</span>
        ${categoryBadge}
        <span class="finding-title">${escHtml(f.title || f.id || '')}</span>
      </div>
      <div class="finding-card-body" id="finding-body-${idx}">
        ${location}
        <div class="finding-section">
          <div class="finding-section-label">Description</div>
          <div class="finding-section-content">${escHtml(f.description || '')}</div>
        </div>
        ${f.exploit ? `<div class="finding-section"><div class="finding-section-label">Exploit</div><div class="finding-section-content">${escHtml(f.exploit)}</div></div>` : ''}
        ${f.impact ? `<div class="finding-section"><div class="finding-section-label">Impact</div><div class="finding-section-content">${escHtml(f.impact)}</div></div>` : ''}
        ${f.evidence ? `<div class="finding-section"><div class="finding-section-label">Evidence</div><pre class="finding-evidence">${escHtml(f.evidence)}</pre></div>` : ''}
      </div>
    </div>`;
  });

  return html;
}

function toggleFinding(idx) {
  const card = document.getElementById('finding-card-' + idx);
  if (card) card.classList.toggle('expanded');
}

function phaseLabel(phase) {
  switch (phase) {
    case 'init': return 'Initializing';
    case 'assemble': return 'Reading source';
    case 'assemble_done': return 'Source assembled';
    case 'analyze': return 'LLM analyzing';
    case 'scan_done': return 'Scan complete';
    case 'done': return 'Complete';
    default: return phase;
  }
}

function phaseIcon(phase) {
  switch (phase) {
    case 'init': return '◯';
    case 'assemble': return '⟳';
    case 'assemble_done': return '✓';
    case 'analyze': return '◈';
    case 'scan_done': return '✓';
    case 'done': return '✓';
    default: return '·';
  }
}

function verdictInfo(verdict, severity) {
  const label = verdict === 'confirmed_vulnerability' ? 'CONFIRMED'
    : verdict === 'hardening_recommendation' ? 'HARDENING'
    : verdict === 'false_positive' ? 'FALSE POSITIVE'
    : verdict === 'inconclusive' ? 'INCONCLUSIVE'
    : (verdict || 'unknown').toUpperCase();
  const cls = verdict === 'confirmed_vulnerability' ? 'tl-confirmed'
    : verdict === 'hardening_recommendation' ? 'tl-hardening'
    : verdict === 'false_positive' ? 'tl-false-positive'
    : 'tl-not-confirmed';
  const sev = severity && severity !== 'NONE' ? ' [' + severity + ']' : '';
  return { label, cls, sev };
}

function loadSavedScans() {
  const btn = document.getElementById('scan-load-btn');
  btn.disabled = true; btn.textContent = 'Loading...';
  const content = document.getElementById('scan-content-dynamic');
  content.innerHTML = '<div class="scan-loading-center"><div class="spinner"></div><div>Loading saved scans...</div></div>';
  setScanStatus('Loading...', 'running');
  api('/api/scan-results?project=juiceshop').then(results => {
    btn.disabled = false; btn.textContent = 'Load Previous';
    if (!results || results.length === 0) {
      content.innerHTML = '<div class="scan-empty">No saved scan results found.</div>';
      setScanStatus('Ready', 'idle');
      return;
    }
    const content2 = document.getElementById('scan-content-dynamic');
    let html = '<div class="scan-saved-list"><div class="section-header">Saved Scan Results</div>';
    results.forEach(r => {
      const ts = r.timestamp ? new Date(r.timestamp).toLocaleString() : '';
      const partial = r.id && r.id.endsWith('_latest') ? ' (partial)' : '';
      html += `<div class="saved-scan-item" onclick="loadScanResult('${escHtml(r.id)}')">
        <span class="saved-scan-test">${escHtml(r.test)}${partial}</span>
        <span class="saved-scan-meta">${r.targets} targets, ${r.confirmed} confirmed</span>
        <span class="saved-scan-time">${escHtml(ts)}</span>
      </div>`;
    });
    html += '</div>';
    content2.innerHTML = html;
    setScanStatus('Ready', 'idle');
  }).catch(e => {
    btn.disabled = false; btn.textContent = 'Load Previous';
    content.innerHTML = `<div class="scan-empty">Failed to load: ${escHtml(e.message)}</div>`;
    setScanStatus('Error', 'error');
  });
}

async function loadScanResult(scanId) {
  setScanStatus('Loading...', 'running');
  const content = document.getElementById('scan-content-dynamic');
  content.innerHTML = '<div class="scan-loading-center"><div class="spinner"></div><div>Loading scan result...</div></div>';
  const data = await api('/api/scan-results?id=' + encodeURIComponent(scanId));
  _currentScanTest = data.test || '';

  // Label Targeted nodes in Neo4j (don't block UI, but store promise for later await)
  if (data.test) {
    _labelTargetsPromise = fetch('/api/label-targets?id=' + encodeURIComponent(scanId)).catch(() => {});
  }

    // Render the same layout as a live scan
    content.innerHTML = `
      <div class="scan-layout">
        <div class="scan-left">
          <div class="scan-left-header done">
            <span id="scan-left-status">${escHtml(data.test.replace(/__/g, ' / ').replace(/_/g, ' '))}</span>
          </div>
          <div class="scan-phases">
            <div class="phase-item done"><span class="phase-icon">✓</span>Planner: ${data.targets} targets</div>
            <div class="phase-item done"><span class="phase-icon">✓</span>Attacker + Verifier: complete</div>
          </div>
        </div>
        <div class="scan-right">
          <div class="scan-targets-section" id="scan-targets-section">
            <div class="section-header">Attack Targets</div>
            <div id="scan-targets-list"></div>
          </div>
          <div class="scan-final-report" id="scan-final-report" style="display:block"></div>
        </div>
      </div>`;

    // Render targets
    const list = document.getElementById('scan-targets-list');
    const targets = data.all_targets || [];
    const attacks = data.all_attacks || [];
    const verifications = data.all_verifications || [];

    let targetsHtml = `<div class="targets-neo4j-bar">
      <button class="neo4j-targets-btn" onclick="openAttackTargetsInNeo4j()">Examine Identified Attack Targets</button>
    </div>`;
    targets.forEach((t, idx) => {
      const tid = 'target-' + idx;
      const atk = attacks[idx] || {};
      const ver = verifications[idx] || {};
      const vi = verdictInfo(ver.verdict, ver.severity);

      targetsHtml += `<div class="target-card-full expanded" id="${tid}">
        <div class="target-card-header" onclick="document.getElementById('${tid}').classList.toggle('expanded')">
          <span class="expand-icon">▶</span>
          <span class="target-prio-badge ${(t.priority||'').toLowerCase()}">${escHtml(t.priority||'?')}</span>
          <span class="target-title">${escHtml(t.id||'target_'+idx)}</span>
          <span class="target-verdict-badge ${vi.cls}">${escHtml(vi.label)}${escHtml(vi.sev)}</span>
        </div>
        <div class="target-card-body">
          <div class="tl-section tl-problem">
            <div class="tl-section-hdr"><span class="tl-step-num">1</span> Problem</div>
            <div class="tl-section-body">
              ${t.property ? `<div class="tl-line">${escHtml(t.property)}</div>` : ''}
              ${t.source_node && t.sink_node ? `<div class="tl-line tl-path-line">${escHtml(t.source_node.display_name||'')} → ${t.control_point ? escHtml(t.control_point.display_name||'') + ' → ' : ''}${escHtml(t.sink_node.display_name||'')}</div>` : ''}
              ${t.preconditions ? `<div class="tl-line tl-dim">Preconditions: ${escHtml(typeof t.preconditions === 'string' ? t.preconditions : JSON.stringify(t.preconditions))}</div>` : ''}
            </div>
          </div>
          <div class="tl-section tl-attacker-section">
            <div class="tl-section-hdr"><span class="tl-step-num">2</span> Attacker</div>
            <div class="tl-section-body">
              ${atk.hypothesis ? `<div class="tl-line">${escHtml(atk.hypothesis)}</div>` : ''}
              ${atk.attack_steps && atk.attack_steps.length ? `<div class="tl-line tl-dim">Steps: ${atk.attack_steps.map(s => escHtml(s)).join('; ')}</div>` : ''}
              ${atk.what_to_assert ? `<div class="tl-line tl-dim">Assert: ${escHtml(atk.what_to_assert)}</div>` : ''}
              ${atk.reasoning && !atk.hypothesis ? `<div class="tl-line tl-dim">${escHtml(atk.reasoning)}</div>` : ''}
              ${atk.classification === 'error' ? `<div class="tl-line tl-dim">Agent failed (timeout or model error)</div>` : ''}
            </div>
          </div>
          <div class="tl-section tl-verifier-section">
            <div class="tl-section-hdr"><span class="tl-step-num">3</span> Verifier</div>
            <div class="tl-section-body">
              <div class="tl-line">Verdict: <span class="tl-badge ${vi.cls}">${escHtml(vi.label)}${escHtml(vi.sev)}</span></div>
              ${ver.evidence ? `<div class="tl-line">${escHtml(ver.evidence)}</div>` : ''}
              ${ver.recommendation ? `<div class="tl-line tl-dim">Recommendation: ${escHtml(ver.recommendation)}</div>` : ''}
              <div class="tl-test-runs-container" data-ver-idx="${idx}"></div>
            </div>
          </div>
        </div>
      </div>`;
    });
    list.innerHTML = targetsHtml;

    // Populate test runs via DOM (avoids backtick issues in template literals)
    verifications.forEach((ver, idx) => {
      if (!ver._test_runs || !ver._test_runs.length) return;
      const container = list.querySelector(`.tl-test-runs-container[data-ver-idx="${idx}"]`);
      if (!container) return;
      ver._test_runs.forEach((tr, tri) => {
        const details = document.createElement('details');
        details.className = 'tl-test-run';
        const summary = document.createElement('summary');
        summary.textContent = 'Test Execution' + (ver._test_runs.length > 1 ? ' #' + (tri + 1) : '');
        details.appendChild(summary);
        const codePre = document.createElement('pre');
        codePre.className = 'tl-code';
        codePre.textContent = tr.code;
        details.appendChild(codePre);
        const outputLabel = document.createElement('div');
        outputLabel.className = 'tl-output-label';
        outputLabel.textContent = 'Output:';
        details.appendChild(outputLabel);
        const outputPre = document.createElement('pre');
        outputPre.className = 'tl-output';
        outputPre.textContent = tr.output;
        details.appendChild(outputPre);
        container.appendChild(details);
      });
    });

    // Render final report
    const report = document.getElementById('scan-final-report');
    report.innerHTML = `<div class="section-header">Final Report</div>
      <div class="scan-report-summary">
        <div class="report-stat"><span class="report-num">${data.targets}</span>targets</div>
        <div class="report-stat"><span class="report-num">${data.confirmed}</span>confirmed</div>
        <div class="report-stat"><span class="report-num">${data.hardening || 0}</span>hardening</div>
        <div class="report-stat"><span class="report-num">${data.elapsed}s</span>time</div>
      </div>
      ${data.usage ? `<div class="scan-report-usage">Cost: $${data.usage.cost_usd} | Tokens: ${((data.usage.input_tokens||0)+(data.usage.output_tokens||0)).toLocaleString()}</div>` : ''}`;

  setScanStatus('Loaded', 'done');
}

function runVulnScan() {
  const testName = scanSelectedTest || document.getElementById('scan-select').value;
  if (!testName) { alert('Select a test first'); return; }
  if (scanMode === 'static') return;
  if (scanRunning) return;
  scanRunning = true;
  _currentScanTest = testName;

  const btn = document.getElementById('scan-run-btn');
  btn.textContent = 'Scanning...';
  btn.classList.add('running');
  setScanStatus('Connecting...', 'running');

  const content = document.getElementById('scan-content-dynamic');
  content.innerHTML = `
    <div class="scan-layout">
      <div class="scan-left">
        <div class="scan-left-header" id="scan-left-header">
          <div class="spinner"></div>
          <span id="scan-left-status">Starting pipeline...</span>
        </div>
        <div class="scan-phases" id="scan-phases">
          <div class="phase-item" id="phase-planner"><span class="phase-icon">○</span>Planner: Identify attack surfaces</div>
          <div class="phase-item" id="phase-attacker"><span class="phase-icon">○</span>Attacker ↔ Verifier: Analyze & confirm</div>
        </div>
        <div class="scan-tool-log" id="scan-tool-log">
          <div class="tool-log-header">Agent Activity</div>
        </div>
      </div>
      <div class="scan-right">
        <div id="vuln-scan-progress" style="display:none"></div>
        <div class="scan-targets-section" id="scan-targets-section" style="display:none">
          <div class="section-header">Attack Targets</div>
          <div id="scan-targets-list"></div>
        </div>
        <div class="scan-final-report" id="scan-final-report" style="display:none"></div>
      </div>
    </div>`;

  const scanEndpoint = '/api/juiceshop/vuln-scan';
  const url = scanEndpoint + '?test=' + encodeURIComponent(testName);
  scanEventSource = new EventSource(url);

  let thinkingBuffer = {};
  let targetFilesRead = {};  // track files read per target index
  let currentTargetIdx = -1;
  let stepCounter = {};  // track step number per target

  scanEventSource.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    const logEl = document.getElementById('scan-tool-log');

    function addToolEntry(agent, tool, args, result, resultLen) {
      const id = 'tool-' + Date.now() + '-' + Math.random().toString(36).substr(2,5);
      const entry = document.createElement('div');
      entry.className = 'tool-entry';
      entry.id = id;
      const argSummary = tool === 'query_graph'
        ? (args.cypher || '').substring(0, 80)
        : tool === 'read_source'
          ? (args.file || '') + (args.start_line ? ':' + args.start_line + '-' + args.end_line : '')
          : tool === 'run_test'
            ? args.code_length + ' chars'
            : JSON.stringify(args).substring(0, 60);
      const truncated = resultLen > 1500 ? ' (truncated)' : '';
      entry.innerHTML = `
        <div class="tool-entry-header" onclick="document.getElementById('${id}').classList.toggle('expanded')">
          <span class="tool-agent-badge ${agent}">${agent}</span>
          <span class="tool-name">${escHtml(tool)}</span>
          <span class="tool-args-preview">${escHtml(argSummary)}</span>
        </div>
        <div class="tool-entry-body">
          <div class="tool-detail-section">
            <div class="tool-detail-label">Arguments</div>
            <pre class="tool-detail-pre">${escHtml(JSON.stringify(args, null, 2))}</pre>
          </div>
          <div class="tool-detail-section">
            <div class="tool-detail-label">Result${truncated}</div>
            <pre class="tool-detail-pre">${escHtml(result)}</pre>
          </div>
        </div>`;
      logEl.appendChild(entry);
    }

    function addLogNote(icon, text, cls) {
      const entry = document.createElement('div');
      entry.className = 'tool-log-note' + (cls ? ' ' + cls : '');
      entry.innerHTML = `<span class="tool-log-icon">${icon}</span>${escHtml(text)}`;
      logEl.appendChild(entry);
    }

    function nextStep(idx) {
      if (!stepCounter[idx]) stepCounter[idx] = 0;
      stepCounter[idx]++;
      return stepCounter[idx];
    }

    // verdictInfo is defined at top level

    switch (msg.type) {
      case 'phase': {
        const phaseId = (msg.agent === 'verifier') ? 'attacker' : msg.agent;
        const el = document.getElementById('phase-' + phaseId);
        if (!el) break;
        if (msg.status === 'running') {
          el.className = 'phase-item active';
          el.querySelector('.phase-icon').textContent = '↻';
          document.getElementById('scan-left-status').textContent = msg.agent + ' running...';
          setScanStatus(msg.agent + ' running', 'running');
          addLogNote('▶', msg.agent + ' phase started', 'phase-start');
        } else if (msg.status === 'done') {
          if (msg.agent === 'verifier' || msg.agent === 'planner') {
            el.className = 'phase-item done';
            el.querySelector('.phase-icon').textContent = '✓';
          }
          const extra = msg.targets ? ` — ${msg.targets} targets` : msg.reachable !== undefined ? ` — ${msg.reachable} reachable` : '';
          addLogNote('✓', msg.agent + ' complete' + extra, 'phase-done');
        }
        break;
      }

      case 'tool_call': {
        addToolEntry(msg.agent, msg.tool, msg.args, msg.result, msg.result_length);
        // Track files read for current target
        if (currentTargetIdx >= 0 && msg.agent === 'attacker' && (msg.tool === 'read_source' || msg.tool === 'read_test_source')) {
          if (!targetFilesRead[currentTargetIdx]) targetFilesRead[currentTargetIdx] = [];
          const fname = msg.args.file || msg.args.test_file || '';
          if (fname && !targetFilesRead[currentTargetIdx].includes(fname)) {
            targetFilesRead[currentTargetIdx].push(fname);
          }
        }
        break;
      }

      case 'thinking': {
        const key = msg.agent + ':' + (msg.target_id || '');
        if (!thinkingBuffer[key]) thinkingBuffer[key] = '';
        thinkingBuffer[key] += msg.text;
        break;
      }

      case 'targets': {
        document.getElementById('vuln-scan-progress').style.display = 'none';
        const section = document.getElementById('scan-targets-section');
        section.style.display = 'block';
        const list = document.getElementById('scan-targets-list');
        let html = `<div class="targets-neo4j-bar">
          <button class="neo4j-targets-btn" onclick="openAttackTargetsInNeo4j()">Examine Identified Attack Targets</button>
        </div>`;
        msg.targets.forEach((t, idx) => {
          const tid = 'target-' + idx;
          const pathStr = t.path ? (Array.isArray(t.path) ? t.path.join(' → ') : t.path) : '';
          html += `<div class="target-card-full" id="${tid}">
            <div class="target-card-header" onclick="document.getElementById('${tid}').classList.toggle('expanded')">
              <span class="expand-icon">▶</span>
              <span class="target-prio-badge ${(t.priority||'').toLowerCase()}">${escHtml(t.priority||'?')}</span>
              <span class="target-title">${escHtml(t.id||'target_'+idx)}</span>
              <span class="target-verdict-badge" id="${tid}-verdict"></span>
            </div>
            <div class="target-card-body">
              <div class="tl-section tl-problem">
                <div class="tl-section-hdr"><span class="tl-step-num">1</span> Problem</div>
                <div class="tl-section-body">
                  ${t.property ? `<div class="tl-line">${escHtml(t.property)}</div>` : ''}
                  ${t.source_node && t.sink_node ? `<div class="tl-line tl-path-line">${escHtml(t.source_node.display_name||'')} → ${t.control_point ? escHtml(t.control_point.display_name||'') + ' → ' : ''}${escHtml(t.sink_node.display_name||'')}</div>` : ''}
                  ${t.preconditions ? `<div class="tl-line tl-dim">Preconditions: ${escHtml(typeof t.preconditions === 'string' ? t.preconditions : JSON.stringify(t.preconditions))}</div>` : ''}
                </div>
              </div>
              <div class="tl-section tl-attacker-section" id="${tid}-attacker">
                <div class="tl-section-hdr"><span class="tl-step-num">2</span> Attacker</div>
                <div class="tl-section-body" id="${tid}-attacker-body"></div>
              </div>
              <div class="tl-section tl-verifier-section" id="${tid}-verifier">
                <div class="tl-section-hdr"><span class="tl-step-num">3</span> Verifier</div>
                <div class="tl-section-body" id="${tid}-verifier-body"></div>
              </div>
              <div class="tl-summary" id="${tid}-summary"></div>
            </div>
          </div>`;
        });
        list.innerHTML = html;
        break;
      }

      case 'attacker_progress': {
        currentTargetIdx = msg.index;
        targetFilesRead[msg.index] = [];
        document.getElementById('scan-left-status').textContent = msg.target_id + ' (' + (msg.index+1) + '/' + msg.total + ')';
        addLogNote('>', msg.target_id + ' (' + (msg.index+1) + '/' + msg.total + ')');
        const activeCard = document.getElementById('target-' + msg.index);
        if (activeCard) {
          activeCard.classList.add('active');
          activeCard.classList.add('expanded');
        }
        const atkBody = document.getElementById('target-' + msg.index + '-attacker-body');
        if (atkBody) atkBody.innerHTML = '<div class="tl-line tl-working">Reading source code...</div>';
        const verBody = document.getElementById('target-' + msg.index + '-verifier-body');
        if (verBody) verBody.innerHTML = '<div class="tl-line tl-dim">Waiting for attacker...</div>';
        break;
      }

      case 'attack_result': {
        const r = msg.result;
        const idx = msg.index;
        const tcard = document.getElementById('target-' + idx);
        if (tcard) tcard.classList.remove('active');

        const atkBody = document.getElementById('target-' + idx + '-attacker-body');
        if (atkBody) {
          const files = targetFilesRead[idx] || [];
          let html = '';
          if (files.length > 0) {
            html += `<div class="tl-line tl-dim">Read ${files.length} file${files.length > 1 ? 's' : ''}: ${escHtml(files.map(f => f.split('/').pop()).join(', '))}</div>`;
          }
          if (r.hypothesis) {
            html += `<div class="tl-line">${escHtml(r.hypothesis)}</div>`;
          }
          if (r.attack_steps && r.attack_steps.length > 0) {
            html += `<div class="tl-line tl-dim">Steps: ${r.attack_steps.map(s => escHtml(s)).join('; ')}</div>`;
          }
          if (r.what_to_assert) {
            html += `<div class="tl-line tl-dim">Assert: ${escHtml(r.what_to_assert)}</div>`;
          }
          if (r.reasoning && !r.hypothesis) {
            html += `<div class="tl-line tl-dim">${escHtml(r.reasoning)}</div>`;
          }
          if (r.classification === 'error') {
            html += `<div class="tl-line tl-dim">Agent failed (timeout or model error)</div>`;
          }
          atkBody.innerHTML = html;
        }

        // Verifier always runs
        const verBody = document.getElementById('target-' + idx + '-verifier-body');
        if (verBody) {
          verBody.innerHTML = '<div class="tl-line tl-working">Writing and running test...</div>';
        }
        break;
      }

      case 'verifier_progress': {
        document.getElementById('scan-left-status').textContent = 'Verifying: ' + msg.target_id;
        addLogNote('?', 'Verifying: ' + msg.target_id);
        break;
      }


      case 'verification_result': {
        const v = msg.result;
        const idx = msg.index;
        const vi = verdictInfo(v.verdict, v.severity);

        const verBody = document.getElementById('target-' + idx + '-verifier-body');
        if (verBody) {
          let html = '';
          // Verdict
          html += `<div class="tl-line">Verdict: <span class="tl-badge ${vi.cls}">${escHtml(vi.label)}${escHtml(vi.sev)}</span></div>`;
          // Evidence
          if (v.evidence) html += `<div class="tl-line">${escHtml(v.evidence)}</div>`;
          // Recommendation
          if (v.recommendation) html += `<div class="tl-line tl-dim">Recommendation: ${escHtml(v.recommendation)}</div>`;
          verBody.innerHTML = html;
          // Test runs via DOM (avoids backtick issues in template literals)
          if (v._test_runs && v._test_runs.length) {
            v._test_runs.forEach((tr, tri) => {
              const details = document.createElement('details');
              details.className = 'tl-test-run';
              const summary = document.createElement('summary');
              summary.textContent = 'Test Execution' + (v._test_runs.length > 1 ? ' #' + (tri + 1) : '');
              details.appendChild(summary);
              const codePre = document.createElement('pre');
              codePre.className = 'tl-code';
              codePre.textContent = tr.code;
              details.appendChild(codePre);
              const outputLabel = document.createElement('div');
              outputLabel.className = 'tl-output-label';
              outputLabel.textContent = 'Output:';
              details.appendChild(outputLabel);
              const outputPre = document.createElement('pre');
              outputPre.className = 'tl-output';
              outputPre.textContent = tr.output;
              details.appendChild(outputPre);
              verBody.appendChild(details);
            });
          }
        }

        // Verdict badge on header
        const vbadge = document.getElementById('target-' + idx + '-verdict');
        if (vbadge) {
          vbadge.className = 'target-verdict-badge ' + vi.cls;
          vbadge.textContent = vi.label + vi.sev;
        }

        // Summary line
        const summ = document.getElementById('target-' + idx + '-summary');
        if (summ) {
          const summText = v.evidence || v.recommendation || '';
          if (summText) {
            summ.innerHTML = `<div class="tl-summary-text">${escHtml(summText)}</div>`;
          }
        }
        break;
      }

      case 'done': {
        endScanSSE();
        setScanStatus('Complete in ' + msg.elapsed + 's', 'done');
        const hdr = document.getElementById('scan-left-header');
        hdr.classList.add('done');
        document.getElementById('scan-left-status').textContent = 'Done in ' + msg.elapsed + 's';
        document.getElementById('vuln-scan-progress').style.display = 'none';

        const report = document.getElementById('scan-final-report');
        report.style.display = 'block';
        let html = `<div class="section-header">Final Report</div>`;
        html += `<div class="scan-report-summary">
          <div class="report-stat"><span class="report-num">${msg.targets}</span>targets</div>
          <div class="report-stat"><span class="report-num">${msg.reachable}</span>exploitable</div>
          <div class="report-stat"><span class="report-num">${msg.confirmed}</span>confirmed</div>
          <div class="report-stat"><span class="report-num">${msg.elapsed}s</span>time</div>
        </div>`;

        if (msg.usage) {
          const u = msg.usage;
          const inputK = (u.input_tokens / 1000).toFixed(1);
          const outputK = (u.output_tokens / 1000).toFixed(1);
          html += `<div class="scan-usage-summary">
            <span class="usage-item"><b>Tokens:</b> ${inputK}k in / ${outputK}k out</span>
            <span class="usage-item"><b>Cache hit:</b> ${u.cache_hit_pct}%</span>
            <span class="usage-item"><b>Cost:</b> $${u.cost_usd.toFixed(4)}</span>
            <span class="usage-item"><b>Cycles:</b> ${u.cycles}</span>
          </div>`;
        }

        if (!msg.all_attacks || msg.all_attacks.length === 0) {
          html += '<div class="report-no-findings">No attack paths identified.</div>';
        }

        report.innerHTML = html;
        break;
      }

      case 'error':
        endScanSSE();
        setScanStatus('Error', 'error');
        document.getElementById('vuln-scan-progress').innerHTML = '<span style="color:var(--red);">' + escHtml(msg.message) + '</span>';
        document.getElementById('vuln-scan-progress').style.display = 'block';
        break;
    }
  };
  scanEventSource.onerror = () => {
    if (scanRunning) {
      endScanSSE();
      setScanStatus('Connection lost — loading partial results...', 'error');
      // Auto-load partial results after a short delay
      setTimeout(() => {
        const partialId = _currentScanTest + '_latest';
        api('/api/scan-results?id=' + encodeURIComponent(partialId)).then(data => {
          if (data && data.all_targets) {
            const completed = data.completed_targets || data.all_attacks.length;
            setScanStatus(`Loaded ${completed}/${data.targets} targets (connection lost)`, 'done');
            // Render what we have
            loadScanResult(partialId);
          } else {
            setScanStatus('Connection lost — no partial results saved yet', 'error');
          }
        }).catch(() => {
          setScanStatus('Connection lost', 'error');
        });
      }, 2000);
    }
  };
}


function runScan() {
  const testName = scanSelectedTest || document.getElementById('scan-select').value;
  if (!testName) { alert('Select a test first'); return; }
  if (scanRunning) return;
  scanRunning = true;
  scanFindings = [];
  scanStreamText = '';

  const btn = document.getElementById('scan-run-btn');
  btn.textContent = 'Scanning...';
  btn.classList.add('running');
  setScanStatus('Connecting...', 'running');

  const content = document.getElementById('scan-content-dynamic');
  content.innerHTML = `
    <div class="scan-sidebar">
      <div class="scan-sidebar-header" id="scan-sidebar-header">
        <div class="spinner"></div>
        <span id="scan-sidebar-status">Initializing...</span>
      </div>
      <div class="scan-phases" id="scan-phases">
        <div class="phase-item" id="phase-assemble"><span class="phase-icon">◯</span>Assemble source</div>
        <div class="phase-item" id="phase-analyze"><span class="phase-icon">◯</span>Analyze for vulnerabilities</div>
      </div>
      <div class="scan-action-log" id="scan-action-log"></div>
    </div>
    <div class="scan-main" id="scan-main">
      <div class="scan-progress" id="scan-progress">
        <div class="scan-progress-indicator">
          <div class="spinner"></div>
          <span id="scan-progress-text">Starting scan...</span>
        </div>
        <div class="scan-progress-bar-container" id="scan-progress-bar-container" style="display:none">
          <div class="scan-progress-bar" id="scan-progress-bar"></div>
        </div>
      </div>
      <div class="scan-findings" id="scan-findings-panel" style="display:none"></div>
      <div class="scan-usage-bar" id="scan-usage-bar" style="display:none"></div>
    </div>`;

  const url = '/api/review?test=' + encodeURIComponent(testName);
  scanEventSource = new EventSource(url);
  let currentPhase = 'init';
  let stepCount = 0;

  scanEventSource.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    switch (msg.type) {
      case 'progress': {
        const { phase, step, total, message } = msg;
        currentPhase = phase;
        stepCount++;

        // Update sidebar status
        document.getElementById('scan-sidebar-status').textContent = message;
        setScanStatus(phaseLabel(phase), 'running');

        // Update phase indicators
        if (phase === 'assemble' || phase === 'assemble_done') {
          const el = document.getElementById('phase-assemble');
          if (phase === 'assemble_done') {
            el.className = 'phase-item done';
            el.innerHTML = `<span class="phase-icon">✓</span>Source assembled (${step} functions)`;
          } else {
            el.className = 'phase-item active';
            el.innerHTML = `<span class="phase-icon">⟳</span>Reading source (${step}/${total})`;
          }
        }
        if (phase === 'analyze' || phase === 'done') {
          const el = document.getElementById('phase-analyze');
          if (phase === 'done') {
            el.className = 'phase-item done';
            el.innerHTML = `<span class="phase-icon">✓</span>${step} vulnerabilities found`;
          } else {
            el.className = 'phase-item active';
            el.innerHTML = `<span class="phase-icon">⟳</span>Analyzing...`;
          }
        }

        // Update main progress
        const progText = document.getElementById('scan-progress-text');
        if (progText) progText.textContent = message;

        // Show progress bar during assembly
        const barContainer = document.getElementById('scan-progress-bar-container');
        const bar = document.getElementById('scan-progress-bar');
        if (phase === 'assemble' && total > 0) {
          barContainer.style.display = 'block';
          bar.style.width = (step / total * 100) + '%';
        } else if (phase !== 'assemble') {
          barContainer.style.display = 'none';
        }

        // Add to action log
        const logEl = document.getElementById('scan-action-log');
        const entry = document.createElement('div');
        entry.className = 'action-entry';
        entry.innerHTML = `<span class="action-num">${stepCount}</span><span class="phase-badge ${phase}">${phaseIcon(phase)}</span>${escHtml(message)}`;
        logEl.appendChild(entry);
        break;
      }

      case 'stream':
        scanStreamText += msg.text;
        break;

      case 'done': {
        endScanSSE();
        setScanStatus(`Complete in ${msg.elapsed}s`, 'done');
        const sidebarHdr = document.getElementById('scan-sidebar-header');
        sidebarHdr.classList.add('done');
        document.getElementById('scan-sidebar-status').textContent = `Done in ${msg.elapsed}s`;

        // Hide progress, show results
        const progress = document.getElementById('scan-progress');
        if (progress) progress.style.display = 'none';

        const findings = msg.findings || [];
        scanFindings = findings;

        const findingsPanel = document.getElementById('scan-findings-panel');
        findingsPanel.style.display = 'block';
        findingsPanel.innerHTML = renderFindings(findings);

        // Metrics bar
        const usageBar = document.getElementById('scan-usage-bar');
        if (usageBar && msg.metrics) {
          const m = msg.metrics;
          const cacheInfo = m.cache_read_tokens
            ? `<span class="usage-stat cache">Cache: ${(m.cache_read_tokens / 1000).toFixed(1)}k read</span>`
            : '';
          usageBar.style.display = 'flex';
          usageBar.innerHTML = `
            <span class="usage-stat model">${m.model.replace('us.anthropic.', '')}</span>
            <span class="usage-stat">${msg.elapsed}s</span>
            <span class="usage-stat">${(m.input_tokens / 1000).toFixed(1)}k in</span>
            <span class="usage-stat">${(m.output_tokens / 1000).toFixed(1)}k out</span>
            ${cacheInfo}
            <span class="usage-stat cost">$${m.cost.toFixed(4)}</span>
            <span class="usage-stat">${findings.length} vulnerabilities</span>`;
        } else if (usageBar) {
          usageBar.style.display = 'flex';
          usageBar.innerHTML = `<span class="usage-stat">${msg.elapsed}s</span>
            <span class="usage-stat">${findings.length} vulnerabilities</span>`;
        }
        break;
      }

      case 'error':
        endScanSSE();
        setScanStatus('Error: ' + msg.message, 'error');
        document.getElementById('scan-sidebar-status').textContent = 'Error: ' + msg.message;
        const progress2 = document.getElementById('scan-progress');
        if (progress2) progress2.innerHTML = `<div class="scan-progress-indicator" style="color:var(--red);">${escHtml(msg.message)}</div>`;
        break;
    }
  };

  scanEventSource.onerror = () => {
    if (scanRunning) {
      endScanSSE();
      setScanStatus('Connection lost', 'error');
    }
  };
}

// ===== Utilities =====
function escHtml(str) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ===== Init =====
loadGraph();
