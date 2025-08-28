export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      // Razorpay: create order
      if (url.pathname === '/razorpay/order' && request.method === 'POST') {
        const body = await request.json();
        const amountInPaise = String(Math.round(Number(body.amount || '0') * 100));
        const currency = body.currency || 'INR';
        const receipt = body.receipt || ('rcpt_' + crypto.randomUUID());
        const notes = body.notes || {};
        if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
          return json({ error: 'missing_razorpay_keys' }, 500);
        }
        const res = await fetch('https://api.razorpay.com/v1/orders', {
          method: 'POST',
          headers: {
            'Authorization': 'Basic ' + btoa(env.RAZORPAY_KEY_ID + ':' + env.RAZORPAY_KEY_SECRET),
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ amount: amountInPaise, currency, receipt, payment_capture: 1, notes })
        });
        if (!res.ok) {
          const t = await res.text();
          return json({ error: 'create_order_failed', detail: t }, 500);
        }
        const order = await res.json();
        return json({ ok: true, order, keyId: env.RAZORPAY_KEY_ID });
      }

      // Razorpay: verify signature and optionally fetch payment status
      if (url.pathname === '/razorpay/verify' && request.method === 'POST') {
        const body = await request.json();
        const { razorpay_payment_id, razorpay_order_id, razorpay_signature, expectedAmount, product } = body;
        if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
          return json({ error: 'missing_fields' }, 400);
        }
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey('raw', enc.encode(env.RAZORPAY_KEY_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const data = razorpay_order_id + '|' + razorpay_payment_id;
        const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(data));
        const expSig = hex(new Uint8Array(sigBuf));
        if (expSig !== razorpay_signature) {
          return json({ ok: false, reason: 'bad_signature' }, 200);
        }
        // Optional: fetch payment to confirm amount and status
        const pRes = await fetch('https://api.razorpay.com/v1/payments/' + razorpay_payment_id, {
          headers: { 'Authorization': 'Basic ' + btoa(env.RAZORPAY_KEY_ID + ':' + env.RAZORPAY_KEY_SECRET) }
        });
        if (pRes.ok) {
          const p = await pRes.json();
          const amtOk = expectedAmount ? (String(Math.round(Number(expectedAmount) * 100)) === String(p.amount)) : true;
          const statusOk = p.status === 'captured' || p.status === 'authorized';
          if (!amtOk || !statusOk) {
            return json({ ok: false, reason: 'amount_or_status' }, 200);
          }
        }
        const ttlSec = parseInt(env.TOKEN_TTL_SECONDS || '3600');
        const token = await signToken({ product: product || 'ebook', amount: expectedAmount || '99', exp: nowSec() + ttlSec }, env.TOKEN_SECRET);
        const base = env.DOWNLOAD_BASE || url.origin;
        const downloadUrl = base + '/download?token=' + encodeURIComponent(token);
        return json({ ok: true, token, downloadUrl });
      }
      if (url.pathname === '/token/verify' && request.method === 'GET') {
        const token = url.searchParams.get('token') || '';
        const ok = await verifyToken(token, env.TOKEN_SECRET);
        return json({ ok });
      }
      if (url.pathname === '/download' && request.method === 'GET') {
        const token = url.searchParams.get('token') || '';
        const valid = await verifyToken(token, env.TOKEN_SECRET);
        if (!valid) return json({ error: 'invalid_token' }, 403);
        const target = env.DOWNLOAD_TARGET; // e.g., https://your-site/docs/ebook.pdf or R2 signed URL
        if (!target) return json({ error: 'missing_DOWNLOAD_TARGET' }, 500);
        const res = await fetch(target, { cf: { cacheEverything: false } });
        const headers = new Headers(res.headers);
        headers.set('Content-Disposition', 'attachment; filename="ebook.pdf"');
        return new Response(res.body, { status: res.status, headers });
      }
      if (url.pathname === '/paypal/verify' && request.method === 'POST') {
        const body = await request.json();
        const orderId = body.orderId;
        const amount = String(body.expectedAmount || '99');
        const product = body.product || 'ebook';
        if (!orderId) return json({ error: 'missing_orderId' }, 400);
        const verified = await verifyPaypal(orderId, amount, env);
        if (!verified) return json({ ok: false }, 200);
        const ttlSec = parseInt(env.TOKEN_TTL_SECONDS || '3600');
        const token = await signToken({ product, amount, exp: nowSec() + ttlSec }, env.TOKEN_SECRET);
        const base = env.DOWNLOAD_BASE || url.origin;
        const downloadUrl = base + '/download?token=' + encodeURIComponent(token);
        return json({ ok: true, token, downloadUrl });
      }
      if (url.pathname === '/upi/claim' && request.method === 'POST') {
        const body = await request.json();
        const id = crypto.randomUUID();
        const record = { id, receivedAt: new Date().toISOString(), ...body };
        if (env.TOKENS) {
          await env.TOKENS.put('claim:' + id, JSON.stringify(record));
        }
        // Optional: notify via MailChannels if configured
        if (env.MAIL_TO) {
          try { await sendMail(env, record); } catch (e) {}
        }
        return json({ ok: true, id });
      }
      return json({ error: 'not_found' }, 404);
    } catch (e) {
      return json({ error: 'server_error', message: String(e) }, 500);
    }
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });
}

function nowSec(){ return Math.floor(Date.now() / 1000); }

async function signToken(payload, secret) {
  const enc = new TextEncoder();
  const payloadStr = JSON.stringify(payload);
  const payloadB64 = base64url(enc.encode(payloadStr));
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64));
  const sigB64 = base64url(new Uint8Array(sigBuf));
  return payloadB64 + '.' + sigB64;
}

async function verifyToken(token, secret) {
  if (!token || token.indexOf('.') < 0) return false;
  const [payloadB64, sigB64] = token.split('.');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64));
  const expSig = base64url(new Uint8Array(sigBuf));
  if (expSig !== sigB64) return false;
  try {
    const json = JSON.parse(new TextDecoder().decode(fromBase64url(payloadB64)));
    if (typeof json.exp === 'number' && nowSec() > json.exp) return false;
    return true;
  } catch { return false; }
}

function base64url(buf) {
  let b64 = btoa(String.fromCharCode(...buf));
  return b64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function fromBase64url(str) {
  // pad
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function verifyPaypal(orderId, expectedAmount, env) {
  const base = (env.PAYPAL_ENV || 'sandbox') === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const tokenRes = await fetch(base + '/v1/oauth2/token', {
    method: 'POST',
    headers: { 'Authorization': 'Basic ' + btoa(env.PAYPAL_CLIENT_ID + ':' + env.PAYPAL_SECRET), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials'
  });
  if (!tokenRes.ok) return false;
  const tokenJson = await tokenRes.json();
  const access = tokenJson.access_token;
  const orderRes = await fetch(base + '/v2/checkout/orders/' + orderId, { headers: { 'Authorization': 'Bearer ' + access } });
  if (!orderRes.ok) return false;
  const order = await orderRes.json();
  if (order.status !== 'COMPLETED') return false;
  try {
    const amt = order.purchase_units[0].amount.value;
    return String(amt) === String(expectedAmount);
  } catch { return false; }
}

async function sendMail(env, record) {
  const subject = 'New UPI claim #' + record.id;
  const content = 'A new UPI claim was submitted:\n' + JSON.stringify(record, null, 2);
  const resp = await fetch('https://api.mailchannels.net/tx/v1/send', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: env.MAIL_TO }] }],
      from: { email: env.MAIL_FROM || 'noreply@workers.dev', name: 'Portfolio Bot' },
      subject,
      content: [{ type: 'text/plain', value: content }]
    })
  });
  return resp.ok;
}

function hex(buf) {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += buf[i].toString(16).padStart(2, '0');
  return s;
}

