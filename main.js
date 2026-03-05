const API_ENDPOINT = "http://127.0.0.1:5000/predict";
const REQUEST_TIMEOUT = 5000;


// FEATURE EXTRACTION

function extractFeatures(urlString) {
    try {
        const urlObj = new URL(urlString.trim());
        const fullUrl = urlObj.href;
        const hostname = urlObj.hostname;
        const pathname = urlObj.pathname;

        const countChar = (str, char) =>
            (str.match(new RegExp(`\\${char}`, "g")) || []).length;

        const isIpAddress = (str) => {
            const ipPattern =
                /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
            return ipPattern.test(str) ? 1 : 0;
        };

        const digitCount = (fullUrl.match(/\d/g) || []).length;

        return {
            length_url: fullUrl.length,
            length_hostname: hostname.length,
            ip: isIpAddress(hostname),

            nb_dots: countChar(fullUrl, "."),
            nb_hyphens: countChar(fullUrl, "-"),
            nb_slash: countChar(pathname, "/"),
            nb_at: countChar(fullUrl, "@"),
            nb_qm: countChar(fullUrl, "?"),
            nb_and: countChar(fullUrl, "&"),
            nb_eq: countChar(fullUrl, "="),
            nb_underscore: countChar(fullUrl, "_"),
            nb_tilde: countChar(fullUrl, "~"),
            nb_percent: countChar(fullUrl, "%"),
            nb_colon: countChar(fullUrl, ":"),
            nb_semicolumn: countChar(fullUrl, ";"),

            // PERBAIKAN LOGIC
            nb_www: hostname.startsWith("www.") ? 1 : 0,
            nb_com: hostname.endsWith(".com") ? 1 : 0,
            nb_dslash: pathname.includes("//") ? 1 : 0,
            http_in_path: pathname.includes("http") ? 1 : 0,
            https_token: hostname.includes("https") ? 1 : 0,

            ratio_digits_url: fullUrl.length > 0 
                ? digitCount / fullUrl.length 
                : 0
        };

    } catch (err) {
        console.error("Invalid URL:", err);
        return null;
    }
}

function displayAnalysisDetails(features) {
    const detailsGrid = document.getElementById("detailsGrid");
    if (!detailsGrid) return;

    detailsGrid.innerHTML = "";

    const labels = {
        length_url: "Panjang URL",
        length_hostname: "Panjang Hostname",
        ip: "Mengandung IP",
        nb_dots: "Jumlah Titik",
        nb_hyphens: "Jumlah Hyphen",
        nb_slash: "Jumlah Slash (Path)",
        nb_at: "Jumlah @",
        nb_qm: "Jumlah ?",
        nb_and: "Jumlah &",
        nb_eq: "Jumlah =",
        nb_underscore: "Jumlah _",
        nb_tilde: "Jumlah ~",
        nb_percent: "Jumlah %",
        nb_colon: "Jumlah :",
        nb_semicolumn: "Jumlah ;",
        nb_www: "Subdomain www",
        nb_com: "Top-Level .com",
        nb_dslash: "Double Slash (Path)",
        http_in_path: "HTTP di Path",
        https_token: "HTTPS Token di Hostname",
        ratio_digits_url: "Rasio Digit"
    };

    Object.entries(features).forEach(([key, value]) => {
        const div = document.createElement("div");
        div.className = "detail-item";

        div.innerHTML = `
            <span>${labels[key] || key}</span>
            <strong>${value}</strong>
        `;

        detailsGrid.appendChild(div);
    });
}


document.addEventListener("DOMContentLoaded", () => {

    const urlInput = document.getElementById("urlInput");
    const checkBtn = document.getElementById("checkBtn");
    const resultDiv = document.getElementById("result");
    const viewBtn = document.getElementById("viewDetailsBtn");
    const closeBtn = document.getElementById("closeBtn");
    const details = document.getElementById("analysisDetails");

    // Ambil URL aktif
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs?.length && tabs[0]?.url?.startsWith("http")) {
            urlInput.value = tabs[0].url;
        }
    });

    checkBtn.addEventListener("click", async () => {

        resultDiv.classList.remove("hidden");
        resultDiv.innerHTML = "Memeriksa URL...";
        viewBtn.classList.add("hidden");
        closeBtn.classList.add("hidden");

        const features = extractFeatures(urlInput.value);

        if (!features) {
            resultDiv.innerHTML = "❌ URL tidak valid";
            return;
        }

        try {

            // Timeout controller
            const controller = new AbortController();
            const timeoutId = setTimeout(
                () => controller.abort(), 
                REQUEST_TIMEOUT
            );

            const res = await fetch(API_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(features),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!res.ok) {
                throw new Error(`Server error: ${res.status}`);
            }

            const data = await res.json();

            if (!data.label) {
                throw new Error("Invalid server response");
            }

            if (data.label === "phishing") {
                resultDiv.innerHTML = `
                    <div class="warning-header">
                        <div class="warning-icon">⚠️</div>
                        <div style="font-size:18px;font-weight:600;color:red;">
                            SITUS PHISHING TERDETEKSI!
                        </div>
                    </div>
                    <div class="message">
                        Model XGBoost mengidentifikasi situs ini sebagai phishing.
                        Hindari memasukkan informasi pribadi.
                    </div>
                `;
            } else {
                resultDiv.innerHTML = `
                    <div class="warning-header">
                        <div class="warning-icon">✅</div>
                        <div style="font-size:18px;font-weight:600;">
                            Situs Aman Terdeteksi
                        </div>
                    </div>
                    <div class="message">
                        Model XGBoost mengidentifikasi situs ini sebagai aman.
                    </div>
                `;
            }

            displayAnalysisDetails(features);
            viewBtn.classList.remove("hidden");
            closeBtn.classList.remove("hidden");

        } catch (err) {
            console.error(err);

            if (err.name === "AbortError") {
                resultDiv.innerHTML = "❌ Server timeout (lebih dari 5 detik)";
            } else {
                resultDiv.innerHTML = "❌ Gagal terhubung ke server";
            }
        }
    });

    viewBtn.addEventListener("click", () => {
        details.classList.toggle("hidden");
    });

    closeBtn.addEventListener("click", () => {
        resultDiv.classList.add("hidden");
        details.classList.add("hidden");
        viewBtn.classList.add("hidden");
        closeBtn.classList.add("hidden");
    });

});