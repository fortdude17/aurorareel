function el(html){
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

function toast(msg, detail=''){
  const root = document.getElementById('toastRoot');
  if(!root.classList.contains('toast-wrap')) root.className='toast-wrap';
  const node = el(\<div class="toast"><div>\</div><small>\</small></div>\);
  root.appendChild(node);
  setTimeout(()=>{ node.style.opacity='0'; node.style.transform='translateY(6px)'; }, 2800);
  setTimeout(()=>{ node.remove(); }, 3300);
}

function modal(title, bodyNode, actions=[]){
  const root = document.getElementById('modalRoot');
  root.innerHTML = '';
  const backdrop = el(\<div class="modal-backdrop" role="dialog" aria-modal="true"></div>\);
  const box = el(\<div class="modal"><h2>\</h2></div>\);
  box.appendChild(bodyNode);

  const row = el('<div class=\"row\" style=\"margin-top:12px;\"></div>');
  const sp = el('<div class=\"spacer\"></div>');
  row.appendChild(sp);

  for(const a of actions){
    const b = el(\<button class="btn \">\</button>\);
    b.onclick = a.onClick;
    row.appendChild(b);
  }
  box.appendChild(row);

  backdrop.onclick = (e)=>{ if(e.target===backdrop) root.innerHTML=''; };
  backdrop.appendChild(box);
  root.appendChild(backdrop);
}

function escapeHtml(s){
  return String(s??'').replace(/[&<>"']/g, c=>({ '&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;' }[c]));
}

function fmtCount(n){
  n = Number(n||0);
  if(n>=1e6) return (n/1e6).toFixed(1).replace(/\.0$/,'')+'M';
  if(n>=1e3) return (n/1e3).toFixed(1).replace(/\.0$/,'')+'K';
  return String(n);
}
function fmtDate(iso){
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { year:'numeric', month:'short', day:'numeric' });
}
