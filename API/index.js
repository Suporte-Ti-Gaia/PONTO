// RHiD - Coletor de Ponto Diário (Vercel / Node.js)
// Serve a interface e repassa as chamadas ao RHiD (evita bloqueio de CORS).
// Variáveis de ambiente obrigatórias: APP_USER e APP_PASS.
const crypto = require('crypto');
const { HTML } = require('../lib/page.js');

const USER = process.env.APP_USER || '';
const PASS = process.env.APP_PASS || '';
const KEY = USER && PASS ? crypto.createHash('sha256').update(`rhid|${USER}|${PASS}`).digest('hex') : '';

const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function send(res, code, body, type = 'application/json; charset=utf-8', extra = {}) {
  res.statusCode = code;
  res.setHeader('Content-Type', type);
  for (const [k, v] of Object.entries(extra)) res.setHeader(k, v);
  res.end(body);
}

function basicOk(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return false;
  const dec = Buffer.from(h.slice(6), 'base64').toString('utf8');
  const i = dec.indexOf(':');
  if (i < 0) return false;
  return same(dec.slice(0, i), USER) && same(dec.slice(i + 1), PASS);
}

const NO_CREDS = 'Defina APP_USER e APP_PASS em Settings > Environment Variables do projeto na Vercel e faça um novo deploy.';

async function proxy(req, res, target) {
  if (!KEY) return send(res, 503, JSON.stringify({ erro: NO_CREDS }));
  if (!same(req.headers['x-app-key'] || '', KEY)) return send(res, 401, '{"erro":"Nao autorizado"}');
  const host = String(req.headers['x-rhid-host'] || '').trim().replace(/\/+$/, '');
  let u;
  try { u = new URL(host); } catch { return send(res, 400, '{"erro":"Host invalido: use https://www.rhid.com.br"}'); }
  const h = u.hostname;
  if (u.protocol !== 'https:' || !(h === 'rhid.com.br' || h.endsWith('.rhid.com.br')) || u.username || u.port)
    return send(res, 400, '{"erro":"Host invalido: use https://www.rhid.com.br"}');
  if (!target.startsWith('/') || target.startsWith('//')) return send(res, 400, '{"erro":"Caminho invalido"}');

  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body !== undefined && req.body !== null)
    body = typeof req.body === 'string' || Buffer.isBuffer(req.body) ? req.body : JSON.stringify(req.body);
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'rhid-ponto-app/1.0' };
  if (req.headers.authorization) headers.Authorization = req.headers.authorization;
  try {
    const r = await fetch(host + target, { method: req.method, headers, body, signal: AbortSignal.timeout(55000) });
    const buf = Buffer.from(await r.arrayBuffer());
    send(res, r.status, buf, r.headers.get('content-type') || 'application/json');
  } catch (e) {
    send(res, 502, JSON.stringify({ erro: String((e && e.message) || e) }));
  }
}

module.exports = async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const target = url.searchParams.get('u');
  if (target !== null) return proxy(req, res, target);
  if (url.pathname === '/health') return send(res, 200, 'ok', 'text/plain');
  if (!KEY) return send(res, 503, NO_CREDS, 'text/plain; charset=utf-8');
  if (!basicOk(req))
    return send(res, 401, 'Acesso restrito', 'text/plain; charset=utf-8', { 'WWW-Authenticate': 'Basic realm="RHiD Ponto", charset="UTF-8"' });
  send(res, 200, HTML.replace('__APPKEY__', KEY), 'text/html; charset=utf-8', { 'Cache-Control': 'no-store' });
};
