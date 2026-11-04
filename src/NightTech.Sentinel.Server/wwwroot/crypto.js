// Night Tech Sentinel: the tech's signing key and encrypted sessions, with the browser's built-in WebCrypto.
// The signing key is made in this browser and can't be exported, so the server never has it: PCs only do what this
// key signs. Session keys are made fresh for each session.
'use strict';

const SentinelCrypto = (() => {
  const enc = new TextEncoder();
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

  // ---- IndexedDB: this browser's signing key, and the device keys it has seen (trust on first use) ----
  function db() {
    return new Promise((resolve, reject) => {
      const r = indexedDB.open('nighttech-sentinel', 1);
      r.onupgradeneeded = () => { r.result.createObjectStore('keys'); r.result.createObjectStore('devices'); };
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }
  async function get(store, key) {
    const d = await db();
    return new Promise((resolve, reject) => {
      const r = d.transaction(store).objectStore(store).get(key);
      r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
    });
  }
  async function put(store, key, value) {
    const d = await db();
    return new Promise((resolve, reject) => {
      const t = d.transaction(store, 'readwrite');
      t.objectStore(store).put(value, key);
      t.oncomplete = () => resolve(); t.onerror = () => reject(t.error);
    });
  }

  async function keyId(spkiB64) {
    return hex(await crypto.subtle.digest('SHA-256', unb64(spkiB64))).slice(0, 32);
  }

  /** This browser's signing key: { publicKey (base64 SPKI), keyId, privateKey (CryptoKey) } or null. */
  async function signingKey() {
    const k = await get('keys', 'signing');
    return k || null;
  }

  async function makeSigningKey() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const publicKey = b64(await crypto.subtle.exportKey('spki', pair.publicKey));
    const record = { publicKey, keyId: await keyId(publicKey), privateKey: pair.privateKey, made: new Date().toISOString() };
    await put('keys', 'signing', record);
    return record;
  }

  function randomHex(bytes) { return hex(crypto.getRandomValues(new Uint8Array(bytes))); }

  /** Signs a command for one PC. Returns { payload, signature } for the server to pass along. */
  async function signCommand({ deviceId, kind, args = {}, reason = '', tech, minutes = 30 }) {
    const k = await signingKey();
    if (!k) throw new Error('This browser has no signing key yet. Make one in Settings.');
    const now = new Date();
    const command = {
      v: 1, id: randomHex(16), deviceId, kind, args, reason, tech, keyId: k.keyId,
      issuedUtc: new Date(now.getTime() - 60000).toISOString(),
      expiresUtc: new Date(now.getTime() + minutes * 60000).toISOString(),
    };
    const bytes = enc.encode(JSON.stringify(command));
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.privateKey, bytes);
    return { command, signed: { payload: b64(bytes), signature: b64(sig) } };
  }

  /** Remembers a PC's key the first time; afterwards a different key is refused (someone may be in the middle). */
  async function checkDeviceKey(deviceId, spki) {
    const known = await get('devices', deviceId);
    if (!known) { await put('devices', deviceId, spki); return true; }
    return known === spki;
  }

  async function verify(spkiB64, bytes, sigB64) {
    const key = await crypto.subtle.importKey('spki', unb64(spkiB64), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unb64(sigB64), bytes);
  }

  // ---- Encrypted session (matches SessionCrypto in Sentinel's C# code) ----
  async function newSession() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const publicKey = b64(await crypto.subtle.exportKey('spki', pair.publicKey));
    return { sessionId: randomHex(16), pair, publicKey };
  }

  /**
   * Finishes the key exchange once the PC answers. Checks the answer is signed by the PC's own key and is for this
   * session, then returns { seal(bytes), open(frame) }.
   */
  async function completeSession(s, deviceId, devicePublicKey, answer) {
    const payload = unb64(answer.payload);
    if (!await verify(devicePublicKey, payload, answer.signature)) throw new Error("The PC's answer wasn't signed by its own key.");
    const a = JSON.parse(new TextDecoder().decode(payload));
    if (a.sessionId !== s.sessionId || a.deviceId !== deviceId) throw new Error('The answer was for a different session.');
    const theirs = await crypto.subtle.importKey('spki', unb64(a.agentKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirs }, s.pair.privateKey, 256);
    const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
    const salt = await crypto.subtle.digest('SHA-256', enc.encode(s.sessionId));
    const info = enc.encode('NightTech Sentinel session v1|' + s.publicKey + '|' + a.agentKey);
    const keys = new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, hkdf, 512));
    const toAgent = await crypto.subtle.importKey('raw', keys.slice(0, 32), 'AES-GCM', false, ['encrypt']);
    const toBrowser = await crypto.subtle.importKey('raw', keys.slice(32, 64), 'AES-GCM', false, ['decrypt']);
    keys.fill(0);
    let sendCounter = 0n, lastReceived = 0n;
    const iv = c => { const n = new Uint8Array(12); new DataView(n.buffer).setBigUint64(4, c); return n; };
    return {
      computer: a.computer,
      async seal(plain) {
        sendCounter += 1n;
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv(sendCounter), tagLength: 128 }, toAgent, plain));
        const frame = new Uint8Array(8 + ct.length);
        new DataView(frame.buffer).setBigUint64(0, sendCounter);
        frame.set(ct, 8);
        return frame;
      },
      async open(frame) {
        const f = new Uint8Array(frame);
        if (f.length < 24) throw new Error('Frame too short.');
        const c = new DataView(f.buffer, f.byteOffset).getBigUint64(0);
        if (c <= lastReceived) throw new Error('Frame replayed.');
        const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv(c), tagLength: 128 }, toBrowser, f.slice(8));
        lastReceived = c;
        return new Uint8Array(plain);
      },
    };
  }

  const readable = id => id.match(/.{1,4}/g).join(' ');

  return { signingKey, makeSigningKey, signCommand, checkDeviceKey, newSession, completeSession, keyId, readable };
})();
