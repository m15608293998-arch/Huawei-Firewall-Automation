(function () {
  "use strict";

  const PORTAL = window.location.pathname.startsWith("/admin-ui") ? "admin" : "test";
  const STORAGE_PREFIX = `trade-access.oidc.${PORTAL}`;
  const TOKEN_KEY = `${STORAGE_PREFIX}.tokens`;
  const TRANSACTION_KEY = `${STORAGE_PREFIX}.transaction`;
  const FRESH_LOGIN_KEY = `${STORAGE_PREFIX}.fresh-login`;
  let configPromise = null;

  function encodeBase64Url(bytes) {
    let binary = "";
    bytes.forEach((value) => { binary += String.fromCharCode(value); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function randomValue(length = 32) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return encodeBase64Url(bytes);
  }

  async function sha256(value) {
    if (crypto.subtle) {
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value),
      );
      return new Uint8Array(digest);
    }
    return sha256Fallback(value);
  }

  function sha256Fallback(ascii) {
    const maxWord = 2 ** 32;
    const words = [];
    const hash = [];
    const constants = [];
    const isComposite = {};
    let primeCounter = 0;
    for (let candidate = 2; primeCounter < 64; candidate += 1) {
      if (isComposite[candidate]) continue;
      for (let multiple = candidate * candidate; multiple < 313; multiple += candidate) {
        isComposite[multiple] = true;
      }
      hash[primeCounter] = (Math.sqrt(candidate) * maxWord) | 0;
      constants[primeCounter] = (candidate ** (1 / 3) * maxWord) | 0;
      primeCounter += 1;
    }

    const bitLength = ascii.length * 8;
    ascii += "\x80";
    while (ascii.length % 64 !== 56) ascii += "\x00";
    for (let index = 0; index < ascii.length; index += 1) {
      const code = ascii.charCodeAt(index);
      words[index >> 2] |= code << ((3 - index) % 4) * 8;
    }
    words.push(Math.floor(bitLength / maxWord), bitLength);

    for (let block = 0; block < words.length; block += 16) {
      const schedule = words.slice(block, block + 16);
      const oldHash = hash.slice(0);
      let working = hash.slice(0, 8);
      for (let round = 0; round < 64; round += 1) {
        const w15 = schedule[round - 15];
        const w2 = schedule[round - 2];
        const a = working[0];
        const e = working[4];
        const word = round < 16 ? schedule[round] : (
          schedule[round - 16]
          + ((w15 >>> 7 | w15 << 25) ^ (w15 >>> 18 | w15 << 14) ^ (w15 >>> 3))
          + schedule[round - 7]
          + ((w2 >>> 17 | w2 << 15) ^ (w2 >>> 19 | w2 << 13) ^ (w2 >>> 10))
        ) | 0;
        schedule[round] = word;
        const temp1 = (
          working[7]
          + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7))
          + ((e & working[5]) ^ (~e & working[6]))
          + constants[round]
          + word
        ) | 0;
        const temp2 = (
          ((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10))
          + ((a & working[1]) ^ (a & working[2]) ^ (working[1] & working[2]))
        ) | 0;
        working = [(temp1 + temp2) | 0, a, working[1], working[2], (working[3] + temp1) | 0, e, working[5], working[6]];
      }
      for (let index = 0; index < 8; index += 1) hash[index] = (working[index] + oldHash[index]) | 0;
    }

    const bytes = new Uint8Array(32);
    hash.forEach((word, index) => {
      bytes[index * 4] = word >>> 24;
      bytes[index * 4 + 1] = word >>> 16;
      bytes[index * 4 + 2] = word >>> 8;
      bytes[index * 4 + 3] = word;
    });
    return bytes;
  }

  function readJson(key) {
    const raw = sessionStorage.getItem(key);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }

  function writeTokens(payload) {
    const now = Math.floor(Date.now() / 1000);
    const current = readJson(TOKEN_KEY) || {};
    const tokens = {
      ...current,
      ...payload,
      obtained_at: now,
      expires_at: now + Number(payload.expires_in || 0),
    };
    sessionStorage.setItem(TOKEN_KEY, JSON.stringify(tokens));
    return tokens;
  }

  function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(TRANSACTION_KEY);
  }

  async function config() {
    if (!configPromise) {
      configPromise = fetch(`/api/v1/auth/config?portal=${encodeURIComponent(PORTAL)}`, { cache: "no-store" })
        .then(async (response) => {
          if (!response.ok) throw new Error(`OIDC config failed: HTTP ${response.status}`);
          return response.json();
        });
    }
    return configPromise;
  }

  function callbackUri() {
    return `${window.location.origin}${window.location.pathname}`;
  }

  async function exchangeCode(code, transaction) {
    const oidc = await config();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: oidc.client_id,
      code,
      redirect_uri: transaction.redirect_uri,
      code_verifier: transaction.code_verifier,
    });
    const response = await fetch(oidc.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.access_token) {
      throw new Error(payload.error_description || payload.error || "Authorization code exchange failed");
    }
    writeTokens(payload);
  }

  async function initialize() {
    await config();
    const query = new URLSearchParams(window.location.search);
    const error = query.get("error");
    if (error) {
      const detail = query.get("error_description") || error;
      window.history.replaceState({}, document.title, callbackUri());
      throw new Error(detail);
    }

    const code = query.get("code");
    if (code) {
      const transaction = readJson(TRANSACTION_KEY);
      const state = query.get("state");
      if (!transaction || !state || state !== transaction.state) {
        clearSession();
        throw new Error("OIDC state validation failed");
      }
      await exchangeCode(code, transaction);
      sessionStorage.removeItem(TRANSACTION_KEY);
      window.history.replaceState({}, document.title, transaction.redirect_uri);
    }
    if (sessionStorage.getItem(FRESH_LOGIN_KEY) === "1") {
      sessionStorage.removeItem(FRESH_LOGIN_KEY);
      await login({ prompt: "login" });
      return null;
    }
    return readJson(TOKEN_KEY);
  }

  async function login(options = {}) {
    const oidc = await config();
    const state = randomValue();
    const codeVerifier = randomValue(64);
    const codeChallenge = encodeBase64Url(await sha256(codeVerifier));
    const redirectUri = callbackUri();
    sessionStorage.setItem(TRANSACTION_KEY, JSON.stringify({
      state,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
    }));
    const params = new URLSearchParams({
      response_type: "code",
      client_id: oidc.client_id,
      redirect_uri: redirectUri,
      scope: oidc.scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
    if (options.prompt) params.set("prompt", options.prompt);
    window.location.assign(`${oidc.authorization_endpoint}?${params}`);
  }

  async function refresh() {
    const oidc = await config();
    const tokens = readJson(TOKEN_KEY);
    if (!tokens || !tokens.refresh_token) return null;
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: oidc.client_id,
      refresh_token: tokens.refresh_token,
    });
    const response = await fetch(oidc.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.access_token) {
      clearSession();
      return null;
    }
    return writeTokens(payload).access_token;
  }

  async function accessToken(forceRefresh = false) {
    const tokens = readJson(TOKEN_KEY);
    if (!tokens || !tokens.access_token) return null;
    const now = Math.floor(Date.now() / 1000);
    if (!forceRefresh && Number(tokens.expires_at || 0) > now + 30) {
      return tokens.access_token;
    }
    return refresh();
  }

  async function authenticatedFetch(input, init = {}) {
    let token = await accessToken();
    if (!token) throw new Error("LOGIN_REQUIRED");
    const headers = new Headers(init.headers || {});
    headers.set("Authorization", `Bearer ${token}`);
    let response = await fetch(input, { ...init, headers });
    if (response.status !== 401) return response;

    token = await accessToken(true);
    if (!token) return response;
    headers.set("Authorization", `Bearer ${token}`);
    response = await fetch(input, { ...init, headers });
    return response;
  }

  async function logout() {
    const oidc = await config();
    const tokens = readJson(TOKEN_KEY);
    clearSession();
    const params = new URLSearchParams({
      client_id: oidc.client_id,
      post_logout_redirect_uri: callbackUri(),
    });
    if (tokens && tokens.id_token) params.set("id_token_hint", tokens.id_token);
    window.location.assign(`${oidc.logout_endpoint}?${params}`);
  }

  async function loginFresh() {
    const oidc = await config();
    const tokens = readJson(TOKEN_KEY);
    clearSession();
    sessionStorage.setItem(FRESH_LOGIN_KEY, "1");
    const params = new URLSearchParams({
      client_id: oidc.client_id,
      post_logout_redirect_uri: callbackUri(),
    });
    if (tokens && tokens.id_token) params.set("id_token_hint", tokens.id_token);
    window.location.assign(`${oidc.logout_endpoint}?${params}`);
  }

  async function switchAccount() {
    const oidc = await config();
    const tokens = readJson(TOKEN_KEY);
    clearSession();
    const params = new URLSearchParams({
      client_id: oidc.client_id,
      post_logout_redirect_uri: callbackUri(),
    });
    if (tokens && tokens.id_token) params.set("id_token_hint", tokens.id_token);
    window.location.assign(`${oidc.logout_endpoint}?${params}`);
  }

  function isAuthenticated() {
    const tokens = readJson(TOKEN_KEY);
    return Boolean(tokens && tokens.access_token);
  }

  window.tradeAccessOidc = {
    accessToken,
    authenticatedFetch,
    clearSession,
    config,
    initialize,
    isAuthenticated,
    login,
    loginFresh,
    logout,
    switchAccount,
  };
}());
