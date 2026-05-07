const TRUSTED_HOSTS = ['localhost', '127.0.0.1', 'udaycodespace.github.io', 'www.udaycodespace.com'];
const IS_INFO_PAGE = window.location.pathname.includes('/pages/info/');
const IS_NESTED_PAGE = window.location.pathname.includes('/pages/');
const ASSET_BASE = IS_INFO_PAGE ? '../../assets' : (IS_NESTED_PAGE ? '../assets' : './assets');
const ISSUER_REGISTRY_PATH = `${ASSET_BASE}/data/trusted_issuers.json`;
const RESULT_STORE_KEY = 'credify_verify_result_v5';
const TAMPERED_STORE_KEY = 'credify_verify_tampered_v1';
const EMBEDDED_ISSUER_REGISTRY = {
  'did:edu:gprec': {
    name: 'GPREC',
    algorithm: 'PS256',
    publicKeyPem: `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkF5v1ym4AlzX8csMwGhZ
UsXG9MpOOc+vExW561RDcRjjMNBBVF2KHzkhJOKYCSBJwvpJ+IhoWf42tzuhzBY9
8Rrb6heKxaI5PmLDS+pOR16ynZvFulfNItYbo17R+XaTd55ftz3wMmn3nzvvkIxV
Madi7BPJ8s8Y1TR23M76w0WNN4s69z7qdUt21g6LMfwh1bJul2ycaaGNVB1kUIgx
mUGE+YWU8UHLzmcPE7PaVMEfzH96lI1FdEXD2F6dHNRU3T/YGJ2YZA6lCkFi4Bpf
R2CVrtuYNijGk162N9C60oSCzu8UYTI5vwBePmf9R84dlk8Qv0Lv8vUWbxIhoIaX
BFROegACcCBHtENUg4ahktR4G/JbBWSvl35fE9hZku6j3KQJbRDs1h/dbgAfBoLT
gdBftQqxXNRyzrfVT0GtSstnMiPW/AZTtiSxMYoEWyC0u45c59iXfB+NUpliq8lI
Ct7g+alzO6yfFzb3trQjCAiqjaS44FLzxcCO47KzRWZ+DR5qAizkjyCthr6nvsMY
rh7Emujzbg1e8nCfqDPzJT7FAh6Zq7UasMJHQ+1XdTI4rW3s+VSIaIgO1R+/fSoP
mPKXP8/7sUyxRMo/X/dimGQzpaT12DerfFbmVcTaiTPNBnSqR3T7AibUAD4Yg0es
FogAXPXaoh235wypYfOujM0CAwEAAQ==
-----END PUBLIC KEY-----`
  }
};

const page = document.body.dataset.page || 'unknown';
const codeReader = typeof ZXing !== 'undefined' ? new ZXing.BrowserQRCodeReader() : null;
let activeControls = null;
let trustedIssuers = {};

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(text) {
  return String(text ?? 'N/A')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatValue(value) {
  if (Array.isArray(value)) return value.length ? value.join(', ') : 'None';
  return value ?? 'N/A';
}

function decodeBase64Url(str) {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return atob(b64);
}

function bytesFromBase64Url(str) {
  return Uint8Array.from(decodeBase64Url(str), ch => ch.charCodeAt(0));
}

function toUtf8Bytes(text) {
  return new TextEncoder().encode(text);
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', toUtf8Bytes(text));
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function decodeQdPayload(qd) {
  const bytes = bytesFromBase64Url(qd);
  const decoder = new TextDecoder('utf-8');

  try {
    const payloadText = decoder.decode(bytes);
    return { payloadText, parsed: JSON.parse(payloadText) };
  } catch {
    // continue
  }

  if (typeof DecompressionStream === 'function') {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    const decompressed = await new Response(stream).arrayBuffer();
    const payloadText = decoder.decode(new Uint8Array(decompressed));
    return { payloadText, parsed: JSON.parse(payloadText) };
  }

  if (typeof pako !== 'undefined' && typeof pako.ungzip === 'function') {
    const payloadText = pako.ungzip(bytes, { to: 'string' });
    return { payloadText, parsed: JSON.parse(payloadText) };
  }

  throw new Error('This browser cannot decompress the QR payload.');
}

function parseQrPayload(payload) {
  const text = String(payload || '').trim();
  if (!text) throw new Error('The QR payload is empty.');

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new Error('The QR did not contain a valid verification URL.');
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('The QR must contain an HTTP or HTTPS verification URL.');
  }

  const id = url.searchParams.get('id');
  const qk = url.searchParams.get('qk');
  const qd = url.searchParams.get('qd');
  const gt = url.searchParams.get('gt');

  if (!id || !qk) {
    throw new Error('The verification URL is missing one of: id or qk.');
  }

  return {
    credentialId: id,
    qk,
    qd,
    generatedAt: gt ? parseInt(gt, 10) : null,
    sourceUrl: url.toString(),
    sourceHost: url.hostname.toLowerCase(),
    hostTrusted: TRUSTED_HOSTS.includes(url.hostname.toLowerCase())
  };
}

async function loadIssuerRegistry() {
  try {
    const response = await fetch(ISSUER_REGISTRY_PATH, { cache: 'no-cache' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    trustedIssuers = { ...EMBEDDED_ISSUER_REGISTRY, ...(data.issuers || {}) };
  } catch {
    trustedIssuers = { ...EMBEDDED_ISSUER_REGISTRY };
  }
}

function getHashByteLength(hashName) {
  return { 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 }[hashName] || 32;
}

function getSaltLengthCandidates(publicKey) {
  const hashName = publicKey?.algorithm?.hash?.name || 'SHA-256';
  const hashBytes = getHashByteLength(hashName);
  const candidates = [hashBytes];
  const modulusLength = publicKey?.algorithm?.modulusLength;

  if (Number.isFinite(modulusLength)) {
    const emLen = Math.ceil((modulusLength - 1) / 8);
    const legacyMaxSalt = emLen - hashBytes - 2;
    if (legacyMaxSalt > 0) candidates.push(legacyMaxSalt);
  }

  return [...new Set(candidates)];
}

async function verifyRsaPssSignature(publicKey, signatureBytes, signingInputBytes) {
  for (const saltLength of getSaltLengthCandidates(publicKey)) {
    const ok = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength },
      publicKey,
      signatureBytes,
      signingInputBytes
    );
    if (ok) {
      return {
        ok: true,
        saltLength,
        profile: saltLength === 32 ? 'ps256-standard' : 'ps256-legacy-max-salt'
      };
    }
  }
  return { ok: false, profile: 'unverified' };
}

async function verifyJwsToken(qk, payloadText, expectedCid) {
  const parts = String(qk || '').split('.');
  if (parts.length !== 3) {
    return { ok: false, reason: 'Legacy token format detected. This verifier expects JWS QR tokens.' };
  }

  try {
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(decodeBase64Url(headerB64));
    const payload = JSON.parse(decodeBase64Url(payloadB64));
    const issuerId = payload.iss;
    const issuer = trustedIssuers[issuerId];

    if (!issuer?.publicKeyPem) {
      return { ok: false, issuerId, reason: `Trusted issuer configuration missing for ${issuerId || 'unknown issuer'}.` };
    }

    const publicKey = await crypto.subtle.importKey(
      'spki',
      pemToArrayBuffer(issuer.publicKeyPem),
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const verification = await verifyRsaPssSignature(
      publicKey,
      bytesFromBase64Url(signatureB64),
      toUtf8Bytes(`${headerB64}.${payloadB64}`)
    );

    if (!verification.ok) {
      return { ok: false, issuerId, issuerName: issuer.name || issuerId, reason: 'Signature mismatch against trusted issuer key.' };
    }

    if (expectedCid && payload.cid && String(payload.cid) !== String(expectedCid)) {
      return { ok: false, issuerId, issuerName: issuer.name || issuerId, reason: 'Credential ID mismatch between signature and URL.' };
    }

    if (payload.pd && payloadText) {
      const qdHash = await sha256Hex(payloadText);
      if (qdHash !== payload.pd) {
        return { ok: false, issuerId, issuerName: issuer.name || issuerId, reason: 'Payload digest mismatch. QR contents appear altered.' };
      }
    }

    return {
      ok: true,
      issuerId,
      issuerName: issuer.name || issuerId,
      algorithm: header.alg || issuer.algorithm || 'PS256',
      signatureProfile: verification.profile,
      reason: verification.profile === 'ps256-standard'
        ? 'Offline signature validation passed.'
        : 'Offline signature validation passed using legacy issuer compatibility.'
    };
  } catch (error) {
    return { ok: false, reason: `Token verification error: ${String(error)}`.slice(0, 220) };
  }
}

async function verifyPayload(payload, sourceTag) {
  const parsed = parseQrPayload(payload);

  let expiry = {
    hasTimestamp: false,
    isExpired: false,
    ageHours: null,
    ageSeconds: null
  };

  if (parsed.generatedAt) {
    const now = Math.floor(Date.now() / 1000);
    const ageSeconds = now - parsed.generatedAt;
    const expirySeconds = 48 * 60 * 60;
    expiry = {
      hasTimestamp: true,
      isExpired: ageSeconds > expirySeconds,
      ageHours: Math.floor(ageSeconds / 3600),
      ageSeconds
    };
  }

  let decodedQd = null;
  let qdPayloadText = null;

  if (parsed.qd) {
    decodedQd = await decodeQdPayload(parsed.qd);
    qdPayloadText = decodedQd.payloadText;
  }

  const offlineCheck = await verifyJwsToken(parsed.qk, qdPayloadText, parsed.credentialId);

  return {
    decoded: decodedQd?.parsed || { cid: parsed.credentialId },
    hasQdPayload: Boolean(parsed.qd),
    offlineCheck,
    _rawQk: parsed.qk,
    sourceTag,
    sourceHost: parsed.sourceHost,
    hostTrusted: parsed.hostTrusted,
    verificationUrl: parsed.sourceUrl,
    verifiedAt: new Date().toISOString(),
    expiry
  };
}

function storeResult(resultState) {
  sessionStorage.setItem(RESULT_STORE_KEY, JSON.stringify(resultState));
}

function readStoredResult() {
  try {
    const raw = sessionStorage.getItem(RESULT_STORE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function storeTamperedState(state) {
  sessionStorage.setItem(TAMPERED_STORE_KEY, JSON.stringify(state));
}

function readTamperedState() {
  try {
    const raw = sessionStorage.getItem(TAMPERED_STORE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

async function persistAndRedirect(payload, sourceTag) {
  const resultState = await verifyPayload(payload, sourceTag);

  if (!resultState?.offlineCheck?.ok) {
    storeTamperedState({
      reason: resultState?.offlineCheck?.reason || 'Signature validation failed',
      verifiedAt: new Date().toISOString(),
      sourceTag,
      verificationUrl: resultState?.verificationUrl || null
    });
    window.location.assign('./tampered.html');
    return;
  }

  storeResult(resultState);
  window.location.assign('./result.html');
}

function setFeedback(id, text, tone) {
  const node = $(id);
  if (!node) return;

  const tones = {
    idle: 'mt-4 rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600',
    info: 'mt-4 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3 text-sm text-primary',
    success: 'mt-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700',
    error: 'mt-4 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700'
  };

  node.className = tones[tone] || tones.idle;
  node.textContent = text;
}

function renderErrorState(title, message) {
  const heading = $('resultHeading');
  const badge = $('statusBadge');
  const card = $('resultCard');

  if (heading) heading.textContent = title;
  if (badge) {
    badge.className = 'badge badge-error';
    badge.textContent = 'Invalid';
  }
  if (card) {
    card.innerHTML = `
      <section style="border: var(--border-medium) solid var(--slate-700); background: var(--slate-800); padding: 1.5rem;">
        <h2 style="font-size: 1.25rem; font-weight: 600; color: var(--red-500);">${escapeHtml(title)}</h2>
        <p style="margin-top: 1rem; font-size: 0.875rem; line-height: 1.5; color: var(--slate-300);">${escapeHtml(message)}</p>
      </section>
    `;
  }
}

function detailItem(label, value) {
  return `
    <div style="border: var(--border-medium) solid var(--slate-700); background: var(--slate-800); padding: 1rem; color: var(--slate-100);">
      <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--slate-400);">${escapeHtml(label)}</div>
      <div style="margin-top: 0.5rem; word-break: break-word; font-size: 0.875rem; font-weight: 500; line-height: 1.5; color: var(--cyan-400);">${escapeHtml(formatValue(value))}</div>
    </div>
  `;
}

function renderResultState(resultState) {
  const { decoded, hasQdPayload, offlineCheck, sourceTag, sourceHost, hostTrusted, verifiedAt, expiry } = resultState;
  const ok = Boolean(offlineCheck?.ok);
  const expired = Boolean(expiry?.isExpired);
  const withinWindow = Boolean(expiry?.hasTimestamp) && !expired;
  const heading = $('resultHeading');
  const badge = $('statusBadge');
  const card = $('resultCard');

  if (heading) {
    if (ok && withinWindow) heading.textContent = 'Credential verified (within 48 hours)';
    else if (ok && expired) heading.textContent = 'Credential verified (QR expired)';
    else heading.textContent = 'Verification incomplete';
  }

  if (badge) {
    if (ok && withinWindow) {
      badge.className = 'badge badge-success';
      badge.textContent = 'Valid in 48h Window';
    } else if (ok && expired) {
      badge.className = 'badge badge-warning';
      badge.textContent = 'Expired QR (Was Valid)';
    } else {
      badge.className = 'badge badge-warning';
      badge.textContent = 'Review';
    }
  }
  if (!card) return;

  let validityNote = 'QR timestamp unavailable. Signature verification still completed.';
  if (expiry?.hasTimestamp && !expiry?.isExpired) {
    validityNote = `QR is within 48 hours and currently valid (${expiry.ageHours}h old).`;
  } else if (expiry?.isExpired) {
    validityNote = `QR was valid when issued but is now expired (${expiry.ageHours}h old). Ask for a newly downloaded PDF.`;
  }

  card.innerHTML = `
    <section style="border: var(--border-medium) solid var(--slate-700); background: var(--slate-800); padding: 1.5rem; margin-bottom: 1.5rem;">
      <h2 style="margin-top: 0; font-size: 1.4rem; color: var(--cyan-400);">${ok ? 'Offline issuer validation passed' : 'Offline issuer validation failed'}</h2>
      <p style="margin-top: 0.8rem; color: var(--slate-300);">${escapeHtml(offlineCheck?.reason || 'No verification details available.')}</p>
      <p style="margin-top: 0.7rem; color: ${expired ? 'var(--amber-400)' : 'var(--green-500)'}; font-weight: 600;">${escapeHtml(validityNote)}</p>
      ${!hasQdPayload ? '<p style="margin-top: 0.5rem; font-size: 0.8rem; color: var(--amber-400);">This QR does not include embedded credential details (qd), so identity fields are not shown.</p>' : ''}
      <div style="margin-top: 1rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
        ${detailItem('Issuer', offlineCheck?.issuerName || offlineCheck?.issuerId || 'Unknown')}
        ${detailItem('Algorithm', offlineCheck?.algorithm || 'PS256')}
        ${detailItem('Source', sourceTag || 'camera-scan')}
        ${detailItem('Host', `${hostTrusted ? 'Trusted' : 'Unlisted'}: ${sourceHost || 'Unknown'}`)}
        ${detailItem('Verified At', new Date(verifiedAt).toLocaleString())}
      </div>
    </section>

    <section style="border: var(--border-medium) solid var(--slate-700); background: var(--slate-800); padding: 1.5rem; margin-bottom: 1.5rem;">
      <div style="font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: var(--slate-400);">Credential ID</div>
      <div id="credentialIdValue" style="margin-top: 0.5rem; word-break: break-all; border: var(--border-medium) solid var(--slate-700); background: var(--slate-900); padding: 1rem; font-family: var(--font-mono); font-size: 0.875rem; color: var(--cyan-400);">${escapeHtml(decoded.cid || 'N/A')}</div>
      <button id="copyCredentialBtn" type="button" class="btn-primary" style="margin-top: 0.8rem;">Copy Credential ID</button>
    </section>

    ${hasQdPayload ? `
      <section style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem;">
        ${detailItem('Name', decoded.name)}
        ${detailItem('Roll Number', decoded.studentId || decoded.rollNumber)}
        ${detailItem('Degree / Program', decoded.degree)}
        ${detailItem('Department', decoded.department)}
        ${detailItem('CGPA', decoded.cgpa ? `${decoded.cgpa} / 10.00` : 'N/A')}
        ${detailItem('Conduct', decoded.conduct)}
        ${detailItem('Batch', decoded.batch)}
        ${detailItem('Current Semester & Year', decoded.semester && decoded.year ? `${decoded.semester} / ${decoded.year}` : 'N/A')}
        ${detailItem('Backlog Count', decoded.backlogCount ?? '0')}
        ${detailItem('Graduation Year', decoded.graduationYear)}
        ${detailItem('Subjects', decoded.courses)}
        ${detailItem('Backlogs', decoded.backlogs)}
        ${detailItem('IPFS Reference', decoded.ipfsCid || 'On-chain only')}
        ${detailItem('Issue Date', decoded.issueDate)}
      </section>
    ` : ''}
  `;

  const copyButton = $('copyCredentialBtn');
  if (copyButton) {
    copyButton.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(decoded.cid || '');
        copyButton.textContent = 'Copied';
      } catch {
        copyButton.textContent = 'Copy failed';
      }
      setTimeout(() => {
        copyButton.textContent = 'Copy Credential ID';
      }, 1200);
    });
  }
}

function getLandingPayloadFromUrl() {
  const params = new URLSearchParams(window.location.search);
  if (!params.get('id') || !params.get('qk')) return null;
  return window.location.href;
}

function resolveRoute(target) {
  if (IS_INFO_PAGE) return `../${target}`;
  if (IS_NESTED_PAGE) return `./${target}`;
  return `pages/${target}`;
}

async function initResultPage() {
  await loadIssuerRegistry();

  const landingPayload = getLandingPayloadFromUrl();
  if (landingPayload) {
    try {
      const resultState = await verifyPayload(landingPayload, 'direct-link');

      if (!resultState?.offlineCheck?.ok) {
        storeTamperedState({
          reason: resultState?.offlineCheck?.reason || 'Signature validation failed',
          verifiedAt: new Date().toISOString(),
          sourceTag: 'direct-link',
          verificationUrl: resultState?.verificationUrl || null
        });
        window.location.assign(resolveRoute('tampered.html'));
        return;
      }

      storeResult(resultState);
      renderResultState(resultState);
      return;
    } catch (error) {
      renderErrorState('Verification failed', String(error));
      return;
    }
  }

  const stored = readStoredResult();
  if (stored) {
    renderResultState(stored);
    return;
  }

  renderErrorState('No verification loaded', 'Open this page from a scanned Credify QR verification URL.');
}

function stopScanner(video) {
  if (activeControls && typeof activeControls.stop === 'function') {
    try {
      activeControls.stop();
    } catch {
      // ignore
    }
  }
  activeControls = null;

  const stream = video?.srcObject;
  if (stream?.getTracks) {
    stream.getTracks().forEach(track => {
      try {
        track.stop();
      } catch {
        // ignore
      }
    });
  }

  if (video) video.srcObject = null;
}

function initHomeTicker() {
  const target = $('homeTypeLine');
  if (!target) return;

  const statusLines = [
    'Loading issuer registry... OK',
    'Calibrating camera scanner... OK',
    'Awaiting QR capture for offline validation.'
  ];

  let lineIndex = 0;

  function typeLine(text, cb) {
    target.textContent = '';
    let i = 0;
    const timer = setInterval(() => {
      target.textContent += text.charAt(i);
      i += 1;
      if (i >= text.length) {
        clearInterval(timer);
        setTimeout(cb, 700);
      }
    }, 24);
  }

  function loopLines() {
    typeLine(statusLines[lineIndex], () => {
      lineIndex = (lineIndex + 1) % statusLines.length;
      loopLines();
    });
  }

  loopLines();
}

function initMatrixRain() {
  const canvas = $('matrixRain');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  if (!ctx) return;

  const glyphs = 'CREDIFY01<>/#{}[]*+-';
  const fontSize = 14;
  let columns = 0;
  let drops = [];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    columns = Math.max(1, Math.floor(canvas.width / fontSize));
    drops = Array.from({ length: columns }, () => Math.random() * canvas.height / fontSize);
  }

  function draw() {
    ctx.fillStyle = 'rgba(7, 13, 27, 0.08)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#10b981';
    ctx.font = `${fontSize}px IBM Plex Mono`;

    for (let i = 0; i < drops.length; i += 1) {
      const char = glyphs.charAt(Math.floor(Math.random() * glyphs.length));
      const x = i * fontSize;
      const y = drops[i] * fontSize;
      ctx.fillText(char, x, y);

      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i] += 0.8;
    }
  }

  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 48);
}

function initTamperedPage() {
  const reasonNode = $('tamperedReason');
  if (!reasonNode) return;

  const tampered = readTamperedState();
  if (tampered?.reason) {
    reasonNode.textContent = `Reason: ${tampered.reason}`;
  } else {
    reasonNode.textContent = 'Reason: The QR payload or signature did not match trusted issuer verification rules.';
  }
}

async function initScanPage() {
  await loadIssuerRegistry();

  const startBtn = $('startScanBtn');
  const stopBtn = $('stopScanBtn');
  const camera = $('camera');
  const countdownNode = $('scanCountdown');
  const progressNode = $('scanProgressBar');
  let countdownTimer = null;
  let countdownValue = 20;

  function stopCountdown() {
    if (countdownTimer) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
  }

  function updateCountdownUi(secondsLeft) {
    if (countdownNode) {
      countdownNode.textContent = `Scan window: ${secondsLeft}s`;
    }
    if (progressNode) {
      const pct = Math.max(0, Math.min(100, (secondsLeft / 20) * 100));
      progressNode.style.width = `${pct}%`;
    }
  }

  function resetCountdown() {
    countdownValue = 20;
    updateCountdownUi(countdownValue);
  }

  let scanStartTimestamp = null;
  function startCountdown() {
    stopCountdown();
    resetCountdown();
    scanStartTimestamp = Date.now();
    countdownTimer = setInterval(() => {
      countdownValue -= 1;
      updateCountdownUi(countdownValue);
      if (countdownValue <= 0) {
        stopCountdown();
        stopScanner(camera);
        startBtn.disabled = false;
        stopBtn.disabled = true;
        setFeedback('scanFeedback', 'No QR detected within 20 seconds.\n\nMake sure the QR code is fully inside the green box, increase screen/print brightness, and try again.', 'error');
      }
    }, 1000);
  }

  resetCountdown();

  startBtn?.addEventListener('click', async () => {
    if (!codeReader || activeControls) return;

    startBtn.disabled = true;
    stopBtn.disabled = false;
    setFeedback('scanFeedback', 'Opening camera and waiting for a QR (20s window)...', 'info');

    const prefersRearCamera = Boolean(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
    const constraints = {
      video: {
        facingMode: prefersRearCamera ? { ideal: 'environment' } : { ideal: 'user' },
        width: { ideal: 1920 },
        height: { ideal: 1080 },
        frameRate: { ideal: 30, min: 15 }
      }
    };

    if ('timeBetweenScansMillis' in codeReader) {
      codeReader.timeBetweenScansMillis = 120;
    }

    startCountdown();

    const onResult = async result => {
      if (!result?.text) return;
      const scanEndTimestamp = Date.now();
      const elapsedMs = scanEndTimestamp - (scanStartTimestamp || scanEndTimestamp);
      stopCountdown();
      stopScanner(camera);
      if (elapsedMs > 20000) {
        setFeedback('scanFeedback', 'QR detected, but scan exceeded 20 seconds. Please try again and ensure the QR is fully inside the green box.', 'error');
        return;
      }
      setFeedback('scanFeedback', 'QR captured. Redirecting to result...', 'success');
      try {
        await persistAndRedirect(result.text, 'camera-scan');
      } catch (error) {
        storeTamperedState({
          reason: String(error),
          verifiedAt: new Date().toISOString(),
          sourceTag: 'camera-scan',
          verificationUrl: null
        });
        window.location.assign('./tampered.html');
      }
    };

    try {
      if (typeof codeReader.decodeFromConstraints === 'function') {
        activeControls = await codeReader.decodeFromConstraints(constraints, camera, onResult);
      } else {
        activeControls = await codeReader.decodeFromVideoDevice(null, camera, onResult);
      }

      const stream = camera?.srcObject;
      const track = stream?.getVideoTracks ? stream.getVideoTracks()[0] : null;
      if (track?.applyConstraints) {
        try {
          await track.applyConstraints({ advanced: [{ focusMode: 'continuous' }] });
        } catch {
          // Ignore unsupported camera focus constraints.
        }
      }
    } catch (error) {
      stopCountdown();
      stopScanner(camera);
      startBtn.disabled = false;
      stopBtn.disabled = true;
      setFeedback('scanFeedback', `Camera error: ${String(error)}`, 'error');
    }
  });

  stopBtn?.addEventListener('click', () => {
    stopCountdown();
    stopScanner(camera);
    startBtn.disabled = false;
    stopBtn.disabled = true;
    resetCountdown();
    setFeedback('scanFeedback', 'Camera stopped.', 'idle');
  });
}

document.addEventListener('DOMContentLoaded', async () => {
  initMatrixRain();

  if (page === 'scan') {
    await initScanPage();
  } else if (page === 'result') {
    await initResultPage();
  } else if (page === 'home') {
    initHomeTicker();
  } else if (page === 'tampered') {
    initTamperedPage();
  }
});
