#!/usr/bin/env python3
"""RHiD - Coletor de Ponto Diário.
Uso local: python local/server.py  (sem dependências; abre http://127.0.0.1:8765)
Na Vercel a mesma lógica roda em api/index.js (Node); a interface vem de lib/page.js.
Serve a interface e repassa as chamadas ao RHiD (evita bloqueio de CORS)."""
import base64, hashlib, hmac, os, sys, threading, webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlparse, parse_qs

PORT = 8765
# Proteção opcional (obrigatória ao publicar na internet): defina APP_USER e APP_PASS
APP_USER = os.environ.get("APP_USER", "")
APP_PASS = os.environ.get("APP_PASS", "")
KEY = hashlib.sha256(f"rhid|{APP_USER}|{APP_PASS}".encode()).hexdigest() if APP_USER and APP_PASS else ""


class handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _basic_ok(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            u, _, p = base64.b64decode(h[6:]).decode("utf-8").partition(":")
        except Exception:
            return False
        return hmac.compare_digest(u.encode(), APP_USER.encode()) and hmac.compare_digest(p.encode(), APP_PASS.encode())

    def proxy(self, target):
        if KEY and not hmac.compare_digest(self.headers.get("X-App-Key", "").encode(), KEY.encode()):
            return self._send(401, b'{"erro":"Nao autorizado"}')
        host = self.headers.get("X-Rhid-Host", "").strip().rstrip("/")
        u = urlparse(host)
        h = u.hostname or ""
        if u.scheme != "https" or not (h == "rhid.com.br" or h.endswith(".rhid.com.br")) or u.username or u.port not in (None, 443):
            return self._send(400, b'{"erro":"Host invalido: use https://www.rhid.com.br"}')
        if not target.startswith("/") or target.startswith("//"):
            return self._send(400, b'{"erro":"Caminho invalido"}')
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n) if n else None
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "rhid-ponto-app/1.0"}
        if self.headers.get("Authorization"):
            headers["Authorization"] = self.headers["Authorization"]
        req = Request(host + target, data=data, headers=headers, method=self.command)
        try:
            with urlopen(req, timeout=180) as r:
                self._send(r.status, r.read(), r.headers.get("Content-Type", "application/json"))
        except HTTPError as e:
            self._send(e.code, e.read() or b"{}", e.headers.get("Content-Type", "application/json"))
        except Exception as e:
            self._send(502, ('{"erro":"%s"}' % str(e).replace('"', "'")).encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if "u" in q:
            return self.proxy(q["u"][0])
        if u.path == "/health":
            return self._send(200, b"ok", "text/plain")
        if KEY and not self._basic_ok():
            return self._send(401, b"Acesso restrito", "text/plain; charset=utf-8",
                              {"WWW-Authenticate": 'Basic realm="RHiD Ponto", charset="UTF-8"'})
        self._send(200, HTML.replace("__APPKEY__", KEY).encode("utf-8"), "text/html; charset=utf-8",
                   {"Cache-Control": "no-store", "Content-Disposition": "inline"})

    def do_POST(self):
        q = parse_qs(urlparse(self.path).query)
        if "u" not in q:
            return self._send(400, b'{"erro":"Requisicao invalida"}')
        self.proxy(q["u"][0])

    def log_message(self, *a):
        pass


HTML = r"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RHiD - Ponto Diário</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--tx:#1d2733;--mut:#6b7785;--pri:#1f6feb;--bd:#d9dfe7;--ok:#1a7f37;--er:#c62828}
*{box-sizing:border-box}body{margin:0;font:14px/1.4 system-ui,Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--tx)}
header{background:var(--pri);color:#fff;padding:14px 24px;font-size:18px;font-weight:600}
main{max-width:1200px;margin:20px auto;padding:0 16px;display:grid;gap:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px}
h2{margin:0 0 12px;font-size:15px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:end}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--mut);flex:1;min-width:170px}
input{padding:8px 10px;border:1px solid var(--bd);border-radius:6px;font-size:14px;color:var(--tx)}
button{padding:9px 16px;border:0;border-radius:6px;background:var(--pri);color:#fff;font-weight:600;cursor:pointer}
button.sec{background:#e8edf3;color:var(--tx)}button:disabled{opacity:.5;cursor:default}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.cols{grid-template-columns:1fr}}
.list{border:1px solid var(--bd);border-radius:6px;max-height:220px;overflow:auto;padding:6px}
.list label{flex-direction:row;align-items:center;gap:8px;font-size:13px;color:var(--tx);min-width:0;padding:3px 4px}
.tools{display:flex;gap:8px;margin-bottom:6px;align-items:center}.tools small{color:var(--mut);margin-left:auto}
#msg{font-weight:600}.ok{color:var(--ok)}.er{color:var(--er)}.mut{color:var(--mut)}
.tw{overflow:auto;max-height:520px;border:1px solid var(--bd);border-radius:6px}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:6px 8px;border-bottom:1px solid var(--bd);white-space:nowrap;text-align:left}
th{position:sticky;top:0;background:#eef2f7}pre{max-height:300px;overflow:auto;background:#0f1720;color:#d6e2f0;padding:10px;border-radius:6px;font-size:12px}
.hide{display:none}.phead{display:none}
@media print{@page{size:A4 landscape;margin:10mm}body{background:#fff}header,#login,#filters{display:none!important}
main{margin:0;padding:0;max-width:none}.card{border:0;padding:0}#res h2,#raw{display:none!important}.tw{max-height:none;overflow:visible;border:0}
.phead{display:block;margin-bottom:8px;font-size:12px}table{font-size:10px}th{position:static}td,th{white-space:normal}tr{break-inside:avoid}thead{display:table-header-group}}
</style></head><body>
<header>RHiD · Coletor de Ponto Diário</header>
<main>
<section class="card" id="login"><h2>1. Acesso ao RHiD</h2>
<div class="row">
<label>Servidor (host)<input id="host" value="https://www.rhid.com.br"></label>
<label>Login (e-mail)<input id="email" type="email" autocomplete="username"></label>
<label>Senha<input id="pass" type="password" autocomplete="current-password"></label>
<button id="bLogin">Entrar</button></div></section>

<section class="card hide" id="filters"><h2>2. Filtros</h2>
<div class="row" style="margin-bottom:14px">
<label>Data<input id="dia" type="date"></label>
<label title="Quem tem horário cadastrado iniciando nesses horários (ex.: 19:00 07:00 12/36) mostra só a saída da manhã na data escolhida">Escalas noturnas (início do horário)<input id="noite" value="19:00, 22:00, 23:00"></label></div>
<div class="cols">
<div><div class="tools"><b>Equipamentos</b><button class="sec" data-all="dev">Todos</button><button class="sec" data-none="dev">Nenhum</button><small id="cDev"></small></div><div class="list" id="devs"></div></div>
<div><div class="tools"><b>Departamentos</b><button class="sec" data-all="dep">Todos</button><button class="sec" data-none="dep">Nenhum</button><small id="cDep"></small></div><div class="list" id="deps"></div></div>
</div>
<p class="mut" id="sel"></p>
<div class="row"><button id="bGo">Coletar ponto diário</button><button class="sec hide" id="bCsv">Exportar CSV</button><button class="sec hide" id="bXlsx">Exportar Excel</button><button class="sec hide" id="bPdf">Salvar PDF</button><button class="sec hide" id="bRaw">Ver JSON bruto</button><span id="msg"></span></div>
</section>

<section class="card hide" id="res"><h2>Resultado <span class="mut" id="cnt"></span></h2><div class="phead" id="pHead"></div><div class="tw"><table id="tbl"></table></div><pre class="hide" id="raw"></pre></section>
</main>
<script>
const $=id=>document.getElementById(id);const APPKEY='__APPKEY__';
let token=null,people=[],devices=[],depts=[],rows=[],raws=[],shiftById={};
const sv=localStorage;$('host').value=sv.rhHost||$('host').value;$('email').value=sv.rhEmail||'';
const today=new Date().toISOString().slice(0,10);$('dia').value=today;
function msg(t,c){$('msg').textContent=t;$('msg').className=c||''}

async function api(path,body){
  const r=await fetch('/api/index?u='+encodeURIComponent(path),{method:body?'POST':'GET',
    headers:{'X-App-Key':APPKEY,'X-Rhid-Host':$('host').value.trim(),'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},
    body:body?JSON.stringify(body):undefined});
  const t=await r.text();let j;try{j=JSON.parse(t)}catch{j=t}
  if(r.status===401)throw new Error('Sessão expirada ou credenciais inválidas. Entre novamente.');
  if(!r.ok)throw new Error('Erro '+r.status+': '+(typeof j==='string'?j:JSON.stringify(j)).slice(0,300));
  return j;
}
const dtq=(s,n)=>`?draw=1&start=${s}&length=${n}&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=asc&search%5Bvalue%5D=&search%5Bregex%5D=false`+
  '&columns%5B0%5D%5Bdata%5D=id&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B1%5D%5Bdata%5D=name&columns%5B1%5D%5Bsearchable%5D=true&columns%5B1%5D%5Borderable%5D=true';
async function all(path){let out=[],s=0,tot=Infinity;
  while(s<tot){const j=await api(path+dtq(s,500));const d=j.data||[];out=out.concat(d);tot=j.recordsFiltered??j.recordsTotal??out.length;if(!d.length)break;s+=500}
  return out}

$('bLogin').onclick=async()=>{
  $('bLogin').disabled=true;msg('Autenticando...');
  try{
    const j=await api('/login.svc/',{email:$('email').value.trim(),password:$('pass').value});
    if(!j.accessToken)throw new Error('Login sem accessToken: '+JSON.stringify(j).slice(0,200));
    token=j.accessToken;sv.rhHost=$('host').value;sv.rhEmail=$('email').value;
    msg('Carregando equipamentos, departamentos e funcionários...');
    let shs;[devices,depts,people,shs]=await Promise.all([all('/customerdb/device.svc/a'),all('/customerdb/department.svc/a'),all('/customerdb/person.svc/a_status/ativo'),all('/customerdb/shift.svc/a').catch(()=>[])]);
    shiftById=Object.fromEntries(shs.map(x=>[x.id,x.name||x.description||x.nome||'']));
    $('devs').innerHTML=devices.map(d=>`<label><input type=checkbox data-g=dev value="${d.id}"> ${esc(d.name||('Equip. '+d.id))} <span class=mut>${esc(d.host||'')}</span></label>`).join('')||'<span class=mut>Nenhum equipamento</span>';
    $('deps').innerHTML=depts.map(d=>`<label><input type=checkbox data-g=dep value="${d.id}"> ${esc(d.name)}</label>`).join('')||'<span class=mut>Nenhum departamento</span>';
    $('filters').classList.remove('hide');upd();msg('Conectado.','ok');
  }catch(e){msg(e.message,'er')}finally{$('bLogin').disabled=false}
};
function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
const sel=g=>[...document.querySelectorAll(`input[data-g=${g}]:checked`)].map(x=>+x.value);
document.addEventListener('click',e=>{const a=e.target.dataset;if(a.all||a.none){const g=a.all||a.none;document.querySelectorAll(`input[data-g=${g}]`).forEach(c=>c.checked=!!a.all);upd()}});
document.addEventListener('change',e=>{if(e.target.dataset.g)upd()});

function filtered(){const dp=sel('dep');return dp.length?people.filter(x=>dp.includes(x.idDepartment)):people}
function upd(){$('cDev').textContent=sel('dev').length+' selec.';$('cDep').textContent=sel('dep').length+' selec.';
  $('sel').textContent='Marcações lidas direto dos equipamentos '+(sel('dev').length?'selecionados':'(nenhum marcado = todos)')+' · '+filtered().length+' funcionário(s) ativo(s) no filtro de departamento';}

const fmtV=v=>{if(typeof v==='string'){const m=v.match(/^\/Date\((-?\d+)/);if(m){const d=new Date(+m[1]);return isNaN(d)?v:d.toLocaleString('pt-BR')}}return v};
function findRows(o){const q=[o];while(q.length){const x=q.shift();
  if(Array.isArray(x)){if(x.length&&x[0]&&typeof x[0]==='object')return x;x.forEach(v=>q.push(v))}
  else if(x&&typeof x==='object')Object.values(x).forEach(v=>q.push(v))}return[]}
function flat(o,p='',out={}){for(const[k,v]of Object.entries(o)){const key=p?p+'.'+k:k;
  if(v&&typeof v==='object'&&!Array.isArray(v))flat(v,key,out);else out[key]=Array.isArray(v)?JSON.stringify(v):fmtV(v)}return out}

// Extrai marcações (dateTimeStr = AAAAMMDDHHMM) e horário contratual de qualquer ponto do JSON, agrupando por funcionário
function parse(j,acc,seen){
  const walk=(o,ctx)=>{
    if(Array.isArray(o))return o.forEach(v=>walk(v,ctx));
    if(!o||typeof o!=='object')return;
    let pid=ctx;const id=o.idPerson??(o.person&&o.person.id);
    if(id!=null&&typeof id!=='object')pid=id;
    if(pid!=null&&o.strHorarioContratualSimples)(acc[pid]??={p:[],s:''}).s=o.strHorarioContratualSimples;
    const d=o.dateTimeStr;
    if(pid!=null&&typeof d==='string'&&/^\d{12}$/.test(d)&&(o.hora!==undefined||o.text||o._typeEntradaSaida)&&!o.oculto&&!o.excluded){
      const k=pid+'|'+d;if(!seen.has(k)){seen.add(k);(acc[pid]??={p:[],s:''}).p.push({d:d.slice(0,8),t:d.slice(8,10)+':'+d.slice(10,12)})}
    }
    Object.values(o).forEach(v=>walk(v,pid));
  };walk(j,null);
}
const strs=o=>typeof o==='string'?[o]:(o&&typeof o==='object'?Object.values(o).flatMap(strs):[]);
// AFD: Portaria 1510 (tipo 3: NSR9 3 ddmmaaaa hhmm PIS12) e Portaria 671 (tipo 7: NSR9 7 ISO24 CPF12)
function afdLine(l){
  if(/^\d{9}3\d{8}\d{4}\d{11,12}/.test(l))return{d:l.slice(14,18)+l.slice(12,14)+l.slice(10,12),t:l.slice(18,20)+':'+l.slice(20,22),k:l.slice(22,34).replace(/^0+/,'')};
  if(/^\d{9}7\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(l))return{d:l.slice(10,20).replaceAll('-',''),t:l.slice(21,26),k:l.slice(34,46).replace(/^0+/,'')};
  return null}
$('bGo').onclick=async()=>{
  if(!$('dia').value)return msg('Informe a data.','er');
  const day=$('dia').value.replaceAll('-',''),dv=sel('dev'),devs=devices.filter(d=>!dv.length||dv.includes(d.id));
  if(!devs.length)return msg('Nenhum equipamento disponível.','er');
  const idx={};filtered().forEach(p=>[p.pis,p.cpf].forEach(k=>{const n=String(k??'').replace(/\D/g,'').replace(/^0+/,'');if(n)idx[n]=p}));
  $('bGo').disabled=true;rows=[];raws=[];const acc={},errs=[],unk=new Set();let lines=0;
  try{
    for(const [i,d] of devs.entries()){
      msg(`Lendo equipamento ${i+1}/${devs.length}: ${d.name||d.id}...`);
      try{
        const j=await api(`/report.svc/exporta_arquivo/?tipo=afd&idCompany=${d.linkedCompanyId||0}&idDepartment=0&idCostCenter=0&idPerson=0&ini=${day}&fim=${day}`,[d.id]);
        const L=(typeof j==='string'?j:strs(j).join('\n')).split(/\r?\n/);
        raws.push({equipamento:d.name||d.id,total_linhas:L.length,amostra:L.slice(0,15)});
        for(const l of L){const m=afdLine(l.trim());if(!m||m.d!==day)continue;lines++;
          const p=idx[m.k];if(!p){unk.add(m.k);continue}
          const a=acc[p.id]??={p,t:new Set(),dv:new Set()};a.t.add(m.t);a.dv.add(d.name||('Equip. '+d.id))}
      }catch(e){errs.push((d.name||d.id)+': '+e.message)}
    }
    // horário cadastrado (opcional): só para quem marcou, via apuracao_ponto
    const pids=Object.keys(acc).map(Number),sch={};
    for(let i=0;i<pids.length;i+=50){
      msg('Buscando horário cadastrado...');
      try{const t={};parse(await api('/report.svc/apuracao_ponto',{idPerson:pids.slice(i,i+50),ini:day,fim:day,afdChanges:[],alertId:[],pagina:0}),t,new Set());
        Object.entries(t).forEach(([k,v])=>{if(v.s)sch[k]=v.s})}catch(e){}
    }
    // Escala noturna (ex.: 19:00, 22:00, 23:00 até 07:00, inclusive 12x36): na data escolhida só vale a saída da manhã
    const NIGHT=($('noite').value||'').split(/[,;\s]+/).map(x=>{const m=x.match(/^(\d{1,2}):?(\d{2})$/);return m?m[1].padStart(2,'0')+':'+m[2]:''}).filter(Boolean);
    let nightN=0,nightSkip=0,noSch=0;
    const pe=filtered()[0]||{};raws.unshift({exemplo_campos_horario_do_cadastro:Object.fromEntries(Object.entries(pe).filter(([k])=>/hift|orario/i.test(k))),horarios_carregados:Object.keys(shiftById).length});
    rows=Object.values(acc).map(a=>{
      // Horário cadastrado: nome do horário no cadastro do funcionário (o que aparece no RHiD); se não tiver horas no nome, soma o horário contratual do relatório
      const nm=a.p.shiftAtualName||shiftById[a.p.idShiftAtual]||'',ct=sch[a.p.id]||'',hasT=x=>/\d{1,2}:\d{2}/.test(x);
      const sc=hasT(nm)?nm:(nm&&ct?`${nm} (${ct})`:(nm||ct)),m0=sc.match(/(\d{1,2}):(\d{2})/),start=m0?m0[1].padStart(2,'0')+':'+m0[2]:'';
      if(!sc)noSch++;
      let t=[...a.t].sort();
      const r={'Funcionário':a.p.name,'Departamento':a.p.departmentName||'','Horário cadastrado':sc,'Equipamento':[...a.dv].join(', ')};
      if(start&&NIGHT.includes(start)){
        const am=t.filter(x=>x<'12:00');
        if(!am.length){nightSkip++;return null}
        nightN++;r['Saída']=am[am.length-1];r['Qtd. marcações']=1;r['Marcações extras']='';r['Observação']='Escala noturna: só saída';return r}
      const n=t.length;r['Entrada']=t[0];
      if(n===2){r['Saída']=t[1]}else if(n>=3){r['Saída almoço']=t[1];r['Retorno almoço']=t[2];r['Saída']=t[3]||''}
      r['Qtd. marcações']=n;r['Marcações extras']=t.slice(4).join(' ');return r}).filter(Boolean).sort((x,y)=>x['Funcionário'].localeCompare(y['Funcionário']));
    render();
    const f=$('dia').value.split('-').reverse().join('/');
    let m=lines?`${rows.length} colaborador(es) com marcação em ${f} nos equipamentos.`:`Nenhuma marcação AFD reconhecida em ${f}. Veja o JSON bruto.`;
    if(unk.size&&!sel('dep').length)m+=` ${unk.size} PIS/CPF sem cadastro ativo correspondente.`;
    if(nightN)m+=` ${nightN} em escala noturna (só saída).`;
    if(nightSkip)m+=` ${nightSkip} em escala noturna sem saída na data (omitido).`;
    if(NIGHT.length&&noSch)m+=` ${noSch} sem horário cadastrado (regra noturna não aplicada).`;
    if(errs.length)m+=' Falhas: '+errs.join(' | ');
    msg(m,rows.length&&!errs.length?'ok':'er');
  }catch(e){msg(e.message,'er')}finally{$('bGo').disabled=false}
};
function render(){
  $('res').classList.remove('hide');$('cnt').textContent='('+rows.length+' colaboradores)';
  const cols=['Funcionário','Departamento','Horário cadastrado','Equipamento','Entrada','Saída almoço','Retorno almoço','Saída','Qtd. marcações','Marcações extras','Observação'];window._cols=cols;
  $('tbl').innerHTML='<thead><tr>'+cols.map(c=>`<th>${esc(c)}</th>`).join('')+'</tr></thead>'+rows.map(r=>'<tr>'+cols.map(c=>`<td>${esc(r[c])}</td>`).join('')+'</tr>').join('');
  $('raw').textContent=JSON.stringify(raws,null,1);$('bCsv').classList.toggle('hide',!rows.length);$('bPdf').classList.toggle('hide',!rows.length);$('bXlsx').classList.toggle('hide',!rows.length);
  const nm=(g,l)=>{const ids=sel(g);return ids.length?l.filter(x=>ids.includes(x.id)).map(x=>x.name).join(', '):'todos'};
  $('pHead').innerHTML=`<b>Relatório de ponto diário - ${esc($('dia').value.split('-').reverse().join('/'))}</b><br>Equipamentos: ${esc(nm('dev',devices))} · Departamentos: ${esc(nm('dep',depts))} · ${rows.length} colaborador(es) · Emitido em ${new Date().toLocaleString('pt-BR')}`;
  $('bRaw').classList.remove('hide');
}
// ---- Excel (.xlsx) sem bibliotecas: monta o ZIP (sem compressão) com o XML mínimo da planilha ----
function crc32(b){const t=crc32.t||(crc32.t=Array.from({length:256},(_,n)=>{let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;return c>>>0}));
  let r=-1;for(const x of b)r=t[(r^x)&255]^(r>>>8);return(r^-1)>>>0}
function zip(files){
  const enc=new TextEncoder(),parts=[],cd=[],u16=n=>[n&255,n>>8&255],u32=n=>[n&255,n>>8&255,n>>16&255,n>>>24&255];let off=0;
  for(const[name,txt]of files){
    const nb=enc.encode(name),d=enc.encode(txt),c=crc32(d),L=u32(d.length);
    const lh=new Uint8Array([0x50,0x4b,3,4,20,0,0,0,0,0,0,0,0x21,0,...u32(c),...L,...L,...u16(nb.length),0,0,...nb]);
    cd.push(new Uint8Array([0x50,0x4b,1,2,20,0,20,0,0,0,0,0,0,0,0x21,0,...u32(c),...L,...L,...u16(nb.length),0,0,0,0,0,0,0,0,0,0,0,0,...u32(off),...nb]));
    parts.push(lh,d);off+=lh.length+d.length}
  const cds=cd.reduce((a,x)=>a+x.length,0);
  return new Blob([...parts,...cd,new Uint8Array([0x50,0x4b,5,6,0,0,0,0,...u16(files.length),...u16(files.length),...u32(cds),...u32(off),0,0])],
    {type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'})}
const xe=v=>String(v??'').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g,'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function xlsx(head,data,widths){
  const col=i=>String.fromCharCode(65+i);
  const cell=(v,r,i,st)=>typeof v==='number'?`<c r="${col(i)}${r}"${st}><v>${v}</v></c>`:`<c r="${col(i)}${r}"${st} t="inlineStr"><is><t>${xe(v)}</t></is></c>`;
  const rowsX=[head,...data].map((r,ri)=>`<row r="${ri+1}">`+r.map((v,i)=>cell(v,ri+1,i,ri?'':' s="1"')).join('')+'</row>').join('');
  const X='<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',NS='http://schemas.openxmlformats.org/';
  return zip([
    ['[Content_Types].xml',X+`<Types xmlns="${NS}package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`],
    ['_rels/.rels',X+`<Relationships xmlns="${NS}package/2006/relationships"><Relationship Id="rId1" Type="${NS}officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`],
    ['xl/workbook.xml',X+`<workbook xmlns="${NS}spreadsheetml/2006/main" xmlns:r="${NS}officeDocument/2006/relationships"><sheets><sheet name="Ponto diário" sheetId="1" r:id="rId1"/></sheets></workbook>`],
    ['xl/_rels/workbook.xml.rels',X+`<Relationships xmlns="${NS}package/2006/relationships"><Relationship Id="rId1" Type="${NS}officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="${NS}officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`],
    ['xl/styles.xml',X+`<styleSheet xmlns="${NS}spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`],
    ['xl/worksheets/sheet1.xml',X+`<worksheet xmlns="${NS}spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>${widths.map((w,i)=>`<col min="${i+1}" max="${i+1}" width="${w}" customWidth="1"/>`).join('')}</cols><sheetData>${rowsX}</sheetData></worksheet>`]]);
}
$('bXlsx').onclick=()=>{
  const head=['Funcionário','Horário cadastrado','Entrada','Saída almoço','Retorno almoço','Saída','Quantidade de batidas'];
  const k=['Funcionário','Horário cadastrado','Entrada','Saída almoço','Retorno almoço','Saída'];
  const data=rows.map(r=>[...k.map(c=>r[c]??''),r['Qtd. marcações']||0]);
  const a=document.createElement('a');a.href=URL.createObjectURL(xlsx(head,data,[34,26,10,14,16,10,22]));
  a.download=`ponto_diario_${$('dia').value}.xlsx`;a.click()};
$('bPdf').onclick=()=>{const t=document.title;document.title='ponto_diario_'+$('dia').value;window.print();document.title=t};
$('bRaw').onclick=()=>$('raw').classList.toggle('hide');
$('bCsv').onclick=()=>{const c=window._cols,q=v=>'"'+String(v??'').replaceAll('"','""')+'"';
  const t=[c.map(q).join(';'),...rows.map(r=>c.map(k=>q(r[k])).join(';'))].join('\r\n');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['\ufeff'+t],{type:'text/csv;charset=utf-8'}));
  a.download=`ponto_diario_${$('dia').value}.csv`;a.click()};
</script></body></html>"""

if __name__ == "__main__":
    port = int(os.environ.get("PORT", PORT))
    host = os.environ.get("HOST", "0.0.0.0" if "PORT" in os.environ else "127.0.0.1")
    if host != "127.0.0.1" and not KEY:
        sys.exit("ERRO: para publicar na internet defina as variaveis APP_USER e APP_PASS.")
    srv = ThreadingHTTPServer((host, port), handler)
    print(f"RHiD Ponto Diário rodando em http://{host}:{port}  (Ctrl+C para sair)")
    if host == "127.0.0.1":
        threading.Timer(1, lambda: webbrowser.open(f"http://127.0.0.1:{port}")).start()
    srv.serve_forever()
