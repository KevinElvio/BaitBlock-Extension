// ===================================================================
// BaitBlock - Phishing Detector Extension (Chrome Manifest V3)
// ===================================================================
// File: popup.js
// Fungsi: Mengelola UI popup, ekstraksi fitur, dan komunikasi dengan server ML
// ===================================================================

// ============================================================
// KONFIGURASI & KONSTANTA
// ============================================================

// TLD (Top Level Domain) yang sering digunakan oleh phishing (90.7% phishing rate)
const SUSPICIOUS_TLDS = ['xyz', 'top', 'click', 'loan', 'online', 'site', 'work', 'gq', 'ml', 'tk', 'cf', 'ga', 'buzz', 'shop', 'live'];

// Layanan URL shortener yang umum (indikator potencial phishing)
const SHORTENING_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'tr.im', 'tiny.cc', 'lnkd.in'];

// Brand populer internasional yang sering ditiru phishing (berdasarkan dataset)
// Catatan: Jangan tambahkan brand lokal/indo karena subdomain kampus sah也会 dianggap phishing
const KNOWN_BRANDS = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix', 'instagram', 'twitter', 'whatsapp', 'linkedin', 'dropbox', 'adobe', 'ebay', 'spotify', 'shopify', 'chase', 'wellsfargo', 'citi', 'bankofamerica'];

// ============================================================
// FUNGSI HELPERS
// ============================================================

/**
 * Menghitung jumlah kemunculan karakter tertentu dalam string
 * @param {string} str - String yang akan dicek
 * @param {string} char - Karakter yang akan dicari
 * @returns {number} Jumlah kemunculan karakter
 */
function countChar(str, char) {
  const escaped = char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return (str.match(new RegExp(escaped, 'g')) || []).length;
}

// ============================================================
// EKSTRAKSI FITUR LEKSIKAL (URL-based Features)
// ============================================================

/**
 * Mengekstrak 49 fitur leksikal dari URL
 * Fitur ini diperoleh dari struktur URL itu sendiri tanpa perlu mengakses halaman web
 * @param {string} urlString - URL yang akan dianalisis
 * @returns {object|null} Object berisi 49 fitur atau null jika URL invalid
 */
function extractLexicalFeatures(urlString) {
  if (!urlString || !urlString.trim()) return null;

  let url;
  try {
    url = new URL(urlString.trim());
  } catch (e) { return null; }

  if (!url.protocol.startsWith('http')) return null;

  const href = urlString;
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname.toLowerCase();
  const tld = hostname.split('.').pop() || '';

  const features = {};

  // === FITUR DASAR URL (1-18) ===
  features.length_url = href.length;
  features.length_hostname = hostname.length;
  features.nb_dots = countChar(href, '.');
  features.nb_hyphens = countChar(href, '-');
  features.nb_qm = countChar(href, '?');
  features.nb_eq = countChar(href, '=');
  features.nb_tilde = countChar(href, '~');
  features.nb_percent = countChar(href, '%');
  features.nb_slash = countChar(href, '/');
  features.nb_star = countChar(href, '*');
  features.nb_colon = countChar(href, ':');
  features.nb_semicolumn = countChar(href, ';');
  features.nb_dollar = countChar(href, '\\$');
  features.nb_space = countChar(href, ' ');
  features.nb_www = hostname.startsWith('www.') ? 1 : 0;
  features.nb_com = href.includes('.com') ? 1 : 0;
  features.nb_dslash = countChar(href, '//');
  features.http_in_path = pathname.includes('http') ? 1 : 0;
  features.https_token = href.split('https')[1] ? 1 : 0;

  // === FITUR RASIO DIGIT (19-20) ===
  const digitUrl = (href.match(/\d/g) || []).length;
  const digitHost = (hostname.match(/\d/g) || []).length;
  features.ratio_digits_url = href.length > 0 ? digitUrl / href.length : 0;
  features.ratio_digits_host = hostname.length > 0 ? digitHost / hostname.length : 0;

  // === FITUR TEKNIS (21-28) ===
  features.punycode = hostname.startsWith('xn--') ? 1 : 0;
  features.port = url.port ? parseInt(url.port, 10) : 0;
  features.tld_in_path = pathname.includes('.' + tld) ? 1 : 0;
  const hostParts = hostname.split('.');
  const isMultiTld = ['co.id', 'ac.id', 'go.id', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'or.jp', 'ne.jp', 'co.kr', 'or.kr', 'com.br', 'org.br'].some(t => hostname.endsWith('.' + t));
  features.abnormal_subdomain = isMultiTld ? (hostParts.length > 3 ? 1 : 0) : (hostParts.length > 2 ? 1 : 0);
  features.nb_subdomains = isMultiTld ? Math.max(0, hostParts.length - 3) : Math.max(0, hostParts.length - 2);

  // Registered domain & TLD suffix extraction (matching Python tldextract)
  const registeredDomain = isMultiTld ? hostParts[hostParts.length - 3] : hostParts[hostParts.length - 2];
  const tldSuffix = isMultiTld ? hostParts.slice(-2).join('.') : hostParts[hostParts.length - 1];
  const subdomainStr = isMultiTld ? hostParts.slice(0, -3).join('.') : hostParts.slice(0, -2).join('.');

  features.tld_in_subdomain = tldSuffix && subdomainStr.includes(tldSuffix) ? 1 : 0;

  // === FITUR DOMAIN (29-33) ===
  features.prefix_suffix = /-/.test(registeredDomain) ? 1 : 0;
  features.random_domain = /^[a-z0-9]{15,}$/.test(registeredDomain) ? 1 : 0;
  features.shortening_service = SHORTENING_SERVICES.includes(`${registeredDomain}.${tldSuffix}`) ? 1 : 0;
  features.path_extension = /\.[a-zA-Z0-9]+$/.test(pathname) ? 1 : 0;

  const pathParts = pathname.split('/').filter(p => p);
  features.nb_redirection = pathParts.filter(p => p === '' || p === '..').length;
  features.nb_external_redirection = href.includes('redirect') || href.includes('url=') ? 1 : 0;

  // === FITUR KATA (34-45) ===
  const words = href.replace(/[^a-zA-Z]/g, ' ').split(/\s+/).filter(w => w);
  const hostWords = hostname.replace(/[^a-zA-Z0-9]/g, ' ').split(/\s+/).filter(w => w);
  const pathWords = pathname.replace(/[^a-zA-Z0-9]/g, ' ').split(/\s+/).filter(w => w);

  const minWord = arr => arr.length ? Math.min(...arr.map(w => w.length)) : 0;
  const maxWord = arr => arr.length ? Math.max(...arr.map(w => w.length)) : 0;
  const avgWord = arr => arr.length ? arr.reduce((a, b) => a + b.length, 0) / arr.length : 0;

  features.length_words_raw = words.length;
  features.char_repeat = /(.)\1{4,}/.test(href) ? 1 : 0;
  features.shortest_words_raw = minWord(words);
  features.shortest_word_host = minWord(hostWords);
  features.shortest_word_path = minWord(pathWords);
  features.longest_words_raw = maxWord(words);
  features.longest_word_host = maxWord(hostWords);
  features.longest_word_path = maxWord(pathWords);
  features.avg_words_raw = avgWord(words);
  features.avg_word_host = avgWord(hostWords);
  features.avg_word_path = avgWord(pathWords);

  // === FITUR PHISHING INDIKATOR (46-52) ===
  const phishKeywords = ['login', 'signin', 'verify', 'secure', 'update', 'confirm', 'account', 'password', 'banking'];
  features.phish_hints = phishKeywords.filter(k => href.includes(k)).length;

  features.domain_in_brand = KNOWN_BRANDS.some(b => hostname.includes(b)) ? 1 : 0;
  features.brand_in_subdomain = KNOWN_BRANDS.some(b => hostname.split('.')[0].includes(b)) ? 1 : 0;
  features.brand_in_path = KNOWN_BRANDS.some(b => pathname.includes(b)) ? 1 : 0;
  features.suspecious_tld = SUSPICIOUS_TLDS.includes(tld) ? 1 : 0;
  features.statistical_report = 0;

  return features;
}

// ============================================================
// FITUR DEFAULT (DOM & Third-Party)
// ============================================================

/**
 * Mengambil fitur DOM dari content script
 * Mengirim pesan ke content.js untuk mengambil fitur dari halaman web
 * @param {number} tabId - ID tab yang akan diambil fiturnya
 * @returns {Promise<object>} Fitur DOM dari halaman web
 */
async function getDOMFeatures(tabId) {
  if (!tabId) {
    console.log('Tidak ada tabId, menggunakan default DOM features');
    return getDefaultDOMFeatures();
  }

  try {
    console.log('Mengambil DOM features dari tab:', tabId);
    const response = await Promise.race([
      chrome.tabs.sendMessage(tabId, { action: 'getDOMFeatures' }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000))
    ]);
    console.log('DOM features berhasil diambil:', response);
    return response;
  } catch (error) {
    console.log('Gagal mengambil DOM features:', error.message);
    return getDefaultDOMFeatures();
  }
}

/**
 * Mengembalikan nilai default untuk fitur DOM
 */
function getDefaultDOMFeatures() {
  return {
    nb_hyperlinks: 0, ratio_intHyperlinks: 0, ratio_extHyperlinks: 0, ratio_nullHyperlinks: 0,
    nb_extCSS: 0, ratio_intRedirection: 0, ratio_extRedirection: 0, ratio_intErrors: 0, ratio_extErrors: 0,
    login_form: 0, external_favicon: 0, links_in_tags: 0, submit_email: 0, ratio_intMedia: 0, ratio_extMedia: 0,
    sfh: 0, iframe: 0, popup_window: 0, safe_anchor: 0, onmouseover: 0, right_clic: 0,
    empty_title: 0, domain_in_title: 0, domain_with_copyright: 0
  };
}

// ============================================================
// UI FUNCTIONS
// ============================================================

/**
 * Menampilkan loading spinner dengan pesan
 * @param {string} text - Pesan yang akan ditampilkan
 */
function showLoading(text) {
  document.getElementById('loading').classList.remove('hidden');
  document.getElementById('loadingText').textContent = text;
  document.getElementById('checkBtn').disabled = true;
}

/** Menyembunyikan loading spinner dan mengaktifkan tombol */
function hideLoading() {
  document.getElementById('loading').classList.add('hidden');
  document.getElementById('checkBtn').disabled = false;
}

/**
 * Menampilkan hasil prediksi ke UI
 * @param {object} result - Response dari server ML
 * @param {object} features - Fitur yang diekstrak (untuk detail)
 */
function displayResult(result, features, domFeatures, thirdParty) {
  const resultDiv = document.getElementById('result');
  resultDiv.classList.remove('hidden', 'phishing', 'safe', 'error-result');

  if (result.error) {
    resultDiv.classList.add('error-result');
    resultDiv.innerHTML = `<div class="result-header"><div class="result-icon">⚠️</div><div class="result-title">Error</div></div><p class="result-message">${result.error}</p>`;
    document.getElementById('details').classList.add('hidden');
    return;
  }

  const label = result.label || 'unknown';
  const isPhishing = label.toLowerCase() === 'phishing' || label.toLowerCase() === '1';
  resultDiv.classList.add(isPhishing ? 'phishing' : 'safe');

  const icon = isPhishing ? '🚫' : '✅';
  const title = isPhishing ? 'Situs Phishing Terdeteksi!' : 'Situs Aman';
  const message = isPhishing
    ? 'Model ML mendeteksi website ini sebagai <strong>phishing</strong>.'
    : 'Model ML mendeteksi website ini <strong>aman</strong>.';

  resultDiv.innerHTML = `<div class="result-header"><div class="result-icon">${icon}</div><div class="result-title">${title}</div></div><p class="result-message">${message}</p>`;

  if (features) {
    displayDetails(features, domFeatures, isPhishing, thirdParty);
  }
}

/**
 * Menampilkan detail analisis fitur ke UI
 * @param {object} features - Object berisi fitur leksikal
 * @param {object} domFeatures - Object berisi fitur DOM (dari halaman web)
 * @param {boolean} isPhishing - Apakah terdeteksi phishing
 */
function displayDetails(features, domFeatures, isPhishing, thirdParty) {
  const detailsDiv = document.getElementById('details');
  const urlInfo = document.getElementById('urlInfo');
  const securityFeatures = document.getElementById('securityFeatures');
  const thirdPartyFeatures = document.getElementById('thirdPartyFeatures');
  const riskIndicators = document.getElementById('riskIndicators');

  detailsDiv.classList.remove('hidden');

  const url = new URL(features.url || document.getElementById('urlInput').value);
  const cleanUrl = url.origin + url.pathname;

  urlInfo.innerHTML = `
    <div class="detail-item"><span class="label">Panjang URL</span><span class="value">${features.length_url}</span></div>
    <div class="detail-item"><span class="label">Host</span><span class="value">${url.hostname}</span></div>
    <div class="detail-item"><span class="label">TLD</span><span class="value">${url.hostname.split('.').pop()}</span></div>
    <div class="detail-item"><span class="label">Subdomain</span><span class="value">${features.nb_subdomains}</span></div>
    <div class="detail-item"><span class="label">Protocol</span><span class="value">${url.protocol.replace(':','')}</span></div>
    <div class="detail-item"><span class="label">Port</span><span class="value">${url.port || 'default'}</span></div>
    <div class="detail-item"><span class="label">URL Bersih</span><span class="value" style="word-break:break-all;font-size:11px;">${cleanUrl}</span></div>
  `;

  const dom = domFeatures || {};
  const tp = thirdParty || {};

  securityFeatures.innerHTML = `
    <div class="detail-item ${features.nb_www ? 'safe' : ''}"><span class="label">www</span><span class="value">${features.nb_www ? 'Ada' : 'Tidak'}</span></div>
    <div class="detail-item ${features.suspecious_tld ? 'danger' : 'safe'}"><span class="label">TLD Suspect</span><span class="value">${features.suspecious_tld ? 'Ya' : 'Tidak'}</span></div>
    <div class="detail-item ${features.prefix_suffix ? 'warning' : ''}"><span class="label">Prefix/Suffix</span><span class="value">${features.prefix_suffix ? 'Ya' : 'Tidak'}</span></div>
    <div class="detail-item ${features.shortening_service ? 'danger' : ''}"><span class="label">URL Shortener</span><span class="value">${features.shortening_service ? 'Ya' : 'Tidak'}</span></div>
    <div class="detail-item ${features.random_domain ? 'warning' : ''}"><span class="label">Random Domain</span><span class="value">${features.random_domain ? 'Ya' : 'Tidak'}</span></div>
    <div class="detail-item ${features.phish_hints > 0 ? 'warning' : ''}"><span class="label">Phish Keywords</span><span class="value">${features.phish_hints}</span></div>
    <div class="detail-item ${features.brand_in_subdomain ? 'danger' : ''}"><span class="label">Brand di Subdomain</span><span class="value">${features.brand_in_subdomain ? 'Ya' : 'Tidak'}</span></div>
    <div class="detail-item ${features.nb_dots > 3 ? 'warning' : ''}"><span class="label">Jml Titik</span><span class="value">${features.nb_dots}</span></div>
  `;

  const tpLabels = {
    whois_registered_domain: { label: 'Domain Terdaftar', val: v => v === 0 ? 'Ya' : 'Tidak', cls: v => v === 0 ? 'safe' : 'danger' },
    domain_registration_length: { label: 'Lama Registrasi', val: v => `${v} hari` },
    domain_age: { label: 'Usia Domain', val: v => `${v} hari` },
    web_traffic: { label: 'Web Traffic', val: v => v || 'Tidak ada' },
    dns_record: { label: 'DNS Record', val: v => v === 0 ? 'Ada' : 'Tidak ada', cls: v => v === 0 ? 'safe' : 'danger' },
    google_index: { label: 'Google Index', val: v => v === 0 ? 'Terindeks' : 'Tidak', cls: v => v === 0 ? 'safe' : 'danger' },
    page_rank: { label: 'Page Rank', val: v => v || 'Tidak ada' },
  };

  thirdPartyFeatures.innerHTML = Object.entries(tpLabels).map(([key, cfg]) => {
    const v = tp[key];
    const cssClass = cfg.cls ? cfg.cls(v) : '';
    return `<div class="detail-item ${cssClass}"><span class="label">${cfg.label}</span><span class="value">${cfg.val(v)}</span></div>`;
  }).join('');

  let risks = [];
  if (features.suspecious_tld) risks.push({ text: 'TLD mencurigakan', safe: false });
  if (features.brand_in_subdomain) risks.push({ text: 'Brand di subdomain (100% phishing!)', safe: false });
  if (features.shortening_service) risks.push({ text: 'URL shortener terdeteksi', safe: false });
  if (features.random_domain) risks.push({ text: 'Domain acak terdeteksi', safe: false });
  if (features.prefix_suffix) risks.push({ text: 'Adanya prefix/suffix', safe: false });
  if (features.phish_hints > 0) risks.push({ text: `${features.phish_hints} keyword phising terdeteksi`, safe: false });
  if (features.nb_subdomains > 2) risks.push({ text: 'Terlalu banyak subdomain', safe: false });
  if (features.length_url > 100) risks.push({ text: 'URL terlalu panjang', safe: false });

  if (dom.login_form) risks.push({ text: 'Form login terdeteksi', safe: false });
  if (dom.iframe) risks.push({ text: 'Iframe terdeteksi', safe: false });
  if (dom.onmouseover) risks.push({ text: 'OnMouseOver event', safe: false });
  if (dom.empty_title) risks.push({ text: 'Title halaman kosong', safe: false });
  if (dom.popup_window) risks.push({ text: 'Popup window terdeteksi', safe: false });
  if (dom.right_clic) risks.push({ text: 'Klik kanan diblokir', safe: false });
  if (dom.external_favicon) risks.push({ text: 'Favicon eksternal', safe: false });
  if (dom.sfh) risks.push({ text: 'SFH kosong terdeteksi', safe: false });

  if (risks.length === 0) {
    risks.push({ text: 'Tidak ada indikasi mencurigakan', safe: true });
  }

  riskIndicators.innerHTML = risks.map(r => `
    <div class="risk-item ${r.safe ? 'safe' : ''}">
      <span class="risk-icon">${r.safe ? '✓' : '⚠'}</span>
      <span>${r.text}</span>
    </div>
  `).join('');
}

// ============================================================
// MAIN ANALYSIS FUNCTION
// ============================================================

/**
 * Fungsi utama untuk menjalankan analisis phishing
 * Alur:
 * 1. Ambil URL dari input
 * 2. Ekstrak fitur leksikal dari URL
 * 3. Ambil fitur DOM (dengan timeout)
 * 4. Gabungkan semua fitur (leksikal + DOM + third-party)
 * 5. Kirim ke server Flask untuk prediksi
 * 6. Tampilkan hasil ke UI
 */
async function runAnalysis() {
  const url = document.getElementById('urlInput').value;

  if (!url) {
    displayResult({ error: 'URL tidak ditemukan' }, null, null);
    return;
  }

  showLoading('Menganalisis...');

  const normalizedUrl = url.trim();

  let cleanUrl;
  try {
    const u = new URL(normalizedUrl);
    cleanUrl = u.origin + u.pathname;
  } catch {
    cleanUrl = normalizedUrl;
  }

  const lexicalFeatures = extractLexicalFeatures(cleanUrl);
  if (!lexicalFeatures) {
    hideLoading();
    displayResult({ error: 'URL tidak valid' }, null, null);
    return;
  }

  lexicalFeatures.url = cleanUrl;

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabId = tabs[0]?.id;
  const domFeatures = await getDOMFeatures(tabId);
  const thirdParty = await apiService.fetchThirdPartyFeatures(cleanUrl);

  const allFeatures = { ...lexicalFeatures, ...domFeatures, ...thirdParty };

  try {
    const result = await apiService.predictPhishing(allFeatures);
    hideLoading();
    displayResult(result, lexicalFeatures, domFeatures, thirdParty);
  } catch (error) {
    hideLoading();
    displayResult({ error: `Gagal terhubung ke server: ${error.message}` }, null, null);
  }
}

// ============================================================
// EVENT LISTENERS
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
  const urlInput = document.getElementById('urlInput');
  const checkBtn = document.getElementById('checkBtn');

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs?.[0]?.url?.startsWith('http')) {
      urlInput.value = tabs[0].url;
    } else {
      urlInput.value = 'Tidak dapat mengakses URL';
      checkBtn.disabled = true;
    }
  });

  checkBtn.addEventListener('click', runAnalysis);

  const toggleBtn = document.getElementById('toggleDetails');
  const detailsContent = document.getElementById('detailsContent');

  toggleBtn.addEventListener('click', () => {
    toggleBtn.classList.toggle('active');
    detailsContent.classList.toggle('hidden');
  });
});
