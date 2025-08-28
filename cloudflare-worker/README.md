Cloudflare Worker - Payments Verify and Signed Download

Endpoints:
- POST /paypal/verify { orderId, expectedAmount, product }
  - Verifies PayPal order with PayPal API (sandbox by default), returns { ok, token, downloadUrl }
- GET /token/verify?token=...
  - Validates signed token
- GET /download?token=...
  - Streams the eBook PDF if token is valid, with attachment headers
- POST /upi/claim { name, email, upiId, amount, referenceId, product }
  - Stores claim in KV and optionally emails you via MailChannels

Setup:
1) Install wrangler: npm i -g wrangler
2) cd cloudflare-worker
3) Create KV (optional, for claims archive): wrangler kv namespace create TOKENS
4) Update wrangler.toml: set PAYPAL_* keys, TOKEN_SECRET, DOWNLOAD_BASE, DOWNLOAD_TARGET, and KV ids
5) Deploy: wrangler deploy

Frontend wiring:
- In payments.html, on PayPal approve, POST to https://<your-worker>/paypal/verify with orderId and expectedAmount (99) and redirect to returned downloadUrl.
- For UPI, manual unlock is disabled. Add a link to claim.html for submitting the reference; you will receive an email (if MAIL_TO set) and can reply with a one-time link.

Notes:
- For real protection, do not host the real eBook in the public repo. Upload to R2 or another private store and set DOWNLOAD_TARGET accordingly.

