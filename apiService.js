const API_CONFIG = {
  BASE: "http://127.0.0.1:5000",
  PREDICT: "/predict",
  WHOIS: "/whois",
  DNS: "/dns",
  RANK: "/rank",
  GOOGLE_INDEX: "/google-index",
};

const THIRD_PARTY_FIELDS = [
  { keys: ["whois_registered_domain", "domain_registration_length", "domain_age"], endpoint: API_CONFIG.WHOIS, method: "POST" },
  { keys: ["dns_record"],                                               endpoint: API_CONFIG.DNS,     method: "POST" },
  { keys: ["web_traffic", "page_rank"],                                 endpoint: API_CONFIG.RANK,    method: "GET"  },
  { keys: ["google_index"],                                             endpoint: API_CONFIG.GOOGLE_INDEX, method: "POST", bodyKey: "url" },
];

const THIRD_PARTY_DEFAULTS = {
  whois_registered_domain: 0,
  domain_registration_length: 0,
  domain_age: 0,
  web_traffic: 0,
  dns_record: 0,
  google_index: 0,
  page_rank: 0,
};

(function () {
  async function predictPhishing(features) {
    const resp = await fetch(API_CONFIG.BASE + API_CONFIG.PREDICT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(features),
    });
    if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
    return resp.json();
  }

  function buildRequest(entry, domain, urlString) {
    const endpoint = API_CONFIG.BASE + entry.endpoint + "/" + domain;
    const opts = { method: entry.method };
    if (entry.bodyKey) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify({ [entry.bodyKey]: urlString });
    }
    return { endpoint, options: opts, keys: entry.keys };
  }

  async function fetchThirdPartyFeatures(urlString) {
    let domain;
    try {
      domain = new URL(urlString).hostname;
    } catch {
      return { ...THIRD_PARTY_DEFAULTS };
    }

    const settled = await Promise.allSettled(
      THIRD_PARTY_FIELDS.map((entry) => {
        const { endpoint, options } = buildRequest(entry, domain, urlString);
        return fetch(endpoint, options).then((r) => r.json());
      })
    );

    const merged = { ...THIRD_PARTY_DEFAULTS };
    settled.forEach((result, i) => {
      if (result.status === "fulfilled" && result.value) {
        THIRD_PARTY_FIELDS[i].keys.forEach((key) => {
          if (typeof result.value[key] !== "undefined") {
            merged[key] = Number(result.value[key]);
          }
        });
      }
    });

    return merged;
  }

  window.apiService = {
    predictPhishing,
    fetchThirdPartyFeatures,
    config: API_CONFIG,
  };
})();
