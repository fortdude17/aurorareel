fetch('/api/health')
 .then(r=>r.json())
 .then(d=>document.getElementById('app').innerText='Server OK')
