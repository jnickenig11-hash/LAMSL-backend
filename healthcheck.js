#!/usr/bin/env node
// Simple healthcheck script for local CI/monitoring
// Exits 0 on success, non-zero on failure

const endpoints = [
  '/health',
  '/api/content',
  '/ef-images'
];

const base = process.env.BASE_URL || 'http://localhost:3000';

async function check() {
  let ok = true;
  for (const ep of endpoints) {
    const url = base + ep;
    try {
      const res = await fetch(url, { method: 'GET' });
      if (!res.ok) {
        console.error(`FAIL ${url} -> ${res.status}`);
        ok = false;
        continue;
      }
      const json = await res.text();
      console.log(`OK ${url} -> ${res.status} ${json.slice(0,200)}`);
    } catch (e) {
      console.error(`ERROR ${url} -> ${e.message}`);
      ok = false;
    }
  }
  process.exit(ok ? 0 : 1);
}

check();
