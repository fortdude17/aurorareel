# AuroraReel

A glassy, modern video sharing app (NOT YouTube UI) with YouTube-like ranking signals:
- impressions, clicks, watchtime, satisfaction, negatives
- For You / Fresh / Following feeds
- Range streaming

## Run locally
1) Create Postgres DB and apply schema:
   createdb aurorareel
   psql aurorareel -f server/schema.sql

2) Create server/.env:
PORT=3000
DATABASE_URL=postgres://USER:PASSWORD@localhost:5432/aurorareel
SESSION_SECRET=replace_me_long_random
TRUST_PROXY=0

3) Run:
cd server
npm install
npm start

Open http://localhost:3000

## Deploy behind Cloudflare
- Set TRUST_PROXY=1
- Ensure Express trust proxy is enabled (already)
- Cookies use secure:auto; Cloudflare must send X-Forwarded-Proto=https
- Use SSL/TLS Full (strict) recommended
- Do not cache /api/* or /uploads/*

## Limits
- Videos: 100MB max (server enforced)
- Thumbnails: 10MB max (server enforced)
- Types:
  - video: mp4, webm, mov
  - thumb: png, jpg, jpeg, webp
- Upload rate limit: 5 uploads/hour/user
- Comment + login throttles enabled

