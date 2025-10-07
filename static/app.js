const drop = document.getElementById('drop');
const file = document.getElementById('file');
const meta = document.getElementById('meta');
const archive = document.getElementById('archive');
const matrix = document.getElementById('matrix');
const network = document.getElementById('network');

['dragenter','dragover'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault(); drop.classList.add('drag')}));
['dragleave','drop'].forEach(ev=>drop.addEventListener(ev,e=>{e.preventDefault(); drop.classList.remove('drag')}));

drop.addEventListener('drop', e => {
  const f = [...e.dataTransfer.files].find(x=>x.name.endsWith('.zip')); if (f) upload(f);
});
file.addEventListener('change', e => { if (file.files[0]) upload(file.files[0]); });

async function upload(f){
  [meta,archive,matrix,network].forEach(el => { el.style.display='none'; el.innerHTML=''; });
  const fd = new FormData(); fd.append('file', f);
  const res = await fetch('/analyze', {method:'POST', body: fd});
  const data = await res.json();
  if(!res.ok || data.error){ alert(data.error || 'Upload failed'); return; }
  renderAll(data, f.name);
}

function renderAll(data, name){
  // ---- Preview button ----
  const run = data.run_id;
  const previewBtn = `<a class="btn" href="/runs/${run}/view" target="_blank">Open Creative Preview</a>`;

  // ---- Metadata ----
  const md = Object.assign({}, data.metadata || {});
  meta.innerHTML = `
    <h2>Metadata</h2>
    ${previewBtn}
    <div class="kv" style="margin-top:12px">
      <div>Scan Type</div><div>${esc(md.scan_type||'Web scan')}</div>
      <div>API Version</div><div>${esc(md.api_version||'v1')}</div>
      <div>Unix Timestamp</div><div>${esc(String(md.unix_timestamp||''))}</div>
      <div>Scan Duration</div><div>${esc(String(md.scan_duration||''))} seconds</div>
      <div>Creative Type</div><div>${esc(md.creative_type||'HTML5 Zip')}</div>
      <div>Original Name</div><div>${esc(md.original_name||name||'')}</div>
      <div>Device</div><div>${esc(md.device||'Desktop')}</div>
      <div>Language</div><div>${esc(md.language||'en-US')}</div>
      <div>User-Agent</div><div class="list">${esc(md.user_agent||'')}</div>
    </div>`;
  meta.style.display = 'block';

  // ---- Archive ----
  const rows = (data.archive||[]).map(e => `
    <tr><td>${e.is_dir ? '📁' : '📄'}</td>
        <td>${esc(e.name)}</td>
        <td class="ta-r">${bytes(e.size)}</td>
        <td class="ta-r">${bytes(e.compressed)}</td></tr>`).join('');
  archive.innerHTML = `
    <h2>ZIP Archive</h2>
    <table class="table"><thead>
      <tr><th></th><th>Filename</th><th class="ta-r">File Size</th><th class="ta-r">Compressed</th></tr>
    </thead><tbody>${rows}</tbody></table>`;
  archive.style.display = 'block';

  // ---- Checks + thumbnails with download-as-backup ----
  const thumbs = (data.thumbnails || []);
  const thumbRow = thumbs.length ? `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 16px 0">
      ${thumbs.map(t => `<figure style="margin:0">
        <a href="/runs/${run}/backup.png?t=${t.t_sec}" download="backup_${t.t_sec}.png" title="Download as Backup">
          <img src="${t.png_b64}" alt="${t.t_sec}s" style="height:84px;border-radius:6px;border:1px solid #2a2a30">
        </a>
        <figcaption class="meta" style="text-align:center">${t.t_sec} sec</figcaption>
      </figure>`).join('')}
    </div>` : '';

  const tests = (data.results||[]).map(r => `
    <tr>
      <td>${esc(r.category||'-')}</td>
      <td>${esc(r.label)}</td>
      <td class="ta-r"><span class="badge ${r.status}">${esc(r.value)}</span>
        ${r.help ? `<div class="help">${esc(r.help)}</div>` : ''}</td>
    </tr>`).join('');
  matrix.innerHTML = `<h2>Checks</h2>${thumbRow}
    <table class="table"><thead><tr><th>Category</th><th>Test</th><th class="ta-r">Result</th></tr></thead>
    <tbody>${tests}</tbody></table>`;
  matrix.style.display = 'block';

  // ---- Network table + chart ----
  const net = (data.runtime && data.runtime.network_requests) ? data.runtime.network_requests : [];
  if (net.length){
    const nrows = net.map(n => `
      <tr>
        <td>${esc(short(n.url))}</td>
        <td>${n.status??''}</td>
        <td>${esc(n.protocol||'')}</td>
        <td>${esc(n.enc||'')}</td>
        <td class="ta-r">${n.bytes ? bytes(n.bytes) : ''}</td>
        <td>${esc(n.type||'')}</td>
      </tr>`).join('');
    network.innerHTML = `<h2>Network Requests</h2>
      <div id="netChart" style="height:260px;margin:8px 0 12px 0"></div>
      <table class="table"><thead>
        <tr><th>Resource URL</th><th>Status</th><th>Protocol</th><th>Enc</th><th class="ta-r">Bytes</th><th>Type</th></tr>
      </thead><tbody>${nrows}</tbody></table>`;
    network.style.display = 'block';
    // draw chart (no external libs)
    drawBars("netChart", net.map(n=>({name: short(n.url), size: Number(n.bytes||0)})).slice(0,12));
  }
}

function esc(s){ return String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
function bytes(n){ if(n==null||n==='')return ''; n=Number(n); const u=['B','KB','MB','GB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return (i?n.toFixed(1):n|0)+' '+u[i]; }
function short(u){ try{ const x=new URL(u); return (x.hostname+(x.pathname||'')).slice(0,60); }catch(e){ return (u||'').slice(0,60); } }

// tiny bar chart without dependencies
function drawBars(elId, data){
  const el = document.getElementById(elId);
  const max = Math.max(...data.map(d=>d.size), 1);
  el.innerHTML = data.map(d=>`
    <div style="display:flex;align-items:center;gap:8px;margin:4px 0">
      <div class="list" style="flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(d.name)}</div>
      <div style="width:260px;background:#1b1b1f;border:1px solid #2a2a30;border-radius:6px;height:16px;position:relative">
        <div style="position:absolute;left:0;top:0;bottom:0;width:${(d.size/max*100).toFixed(1)}%;background:#22c55e;border-radius:6px"></div>
      </div>
      <div style="width:80px;text-align:right">${bytes(d.size)}</div>
    </div>`).join('');
}
