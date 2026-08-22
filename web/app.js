async function R(){document.getElementById('status').textContent=JSON.stringify(await(await fetch('/api/status')).json(),null,2)}
document.getElementById('r').onclick=R;
document.getElementById('s').onclick=async()=>{
  const r=await fetch('/api/trial',{method:'POST',headers:{'Content-Type':'application/json'},body:document.getElementById('p').value||'{}'});
  document.getElementById('o').textContent=await r.text(); R();
}; R();
