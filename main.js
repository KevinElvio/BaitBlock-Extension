function extractFeatures(urlString) {
    try {
        const urlObj = new URL(urlString);
        const fullUrl = urlObj.href;
        const hostname = urlObj.hostname;

        const count = (str, char) => (str.match(new RegExp(`\\${char}`, "g")) || []).length;

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
            nb_dots: count(fullUrl, "."),
            nb_hyphens: count(fullUrl, "-"),
            nb_slash: count(fullUrl, "/"),
            nb_at: count(fullUrl, "@"),
            nb_qm: count(fullUrl, "?"),
            nb_and: count(fullUrl, "&"),
            nb_eq: count(fullUrl, "="),
            nb_underscore: count(fullUrl, "_"),
            nb_tilde: count(fullUrl, "~"),
            nb_percent: count(fullUrl, "%"),
            nb_colon: count(fullUrl, ":"),
            nb_semicolumn: count(fullUrl, ";"),
            nb_www: fullUrl.includes("www") ? 1 : 0,
            nb_com: fullUrl.includes(".com") ? 1 : 0,
            nb_dslash: fullUrl.includes("//") ? 1 : 0,
            http_in_path: urlObj.pathname.includes("http") ? 1 : 0,
            https_token: urlObj.protocol === "https:" ? 1 : 0,
            ratio_digits_url: Number((digitCount / fullUrl.length).toFixed(2)),
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
        nb_slash: "Jumlah Slash",
        nb_at: "Jumlah @",
        nb_qm: "Jumlah ?",
        nb_and: "Jumlah &",
        nb_eq: "Jumlah =",
        nb_underscore: "Jumlah _",
        nb_tilde: "Jumlah ~",
        nb_percent: "Jumlah %",
        nb_colon: "Jumlah :",
        nb_semicolumn: "Jumlah ;",
        nb_www: "Mengandung www",
        nb_com: "Mengandung .com",
        nb_dslash: "Double Slash",
        http_in_path: "HTTP di Path",
        https_token: "HTTPS",
        ratio_digits_url: "Rasio Digit",
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
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs?.length && tabs[0].url) {
            document.getElementById("urlInput").value = tabs[0].url;
        }
    });
});

document.getElementById("checkBtn").addEventListener("click", async () => {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");
    const viewBtn = document.getElementById("viewDetailsBtn");
    const closeBtn = document.getElementById("closeBtn");

    resultDiv.classList.remove("hidden");
    resultDiv.innerHTML = "Memeriksa URL...";
    viewBtn.classList.add("hidden");
    closeBtn.classList.add("hidden");

    const features = extractFeatures(url);
    if (!features) {
        resultDiv.innerHTML = "❌ URL tidak valid";
        return;
    }
    console.log(features);


    try {
        const res = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(features),
        });

        if (!res.ok) throw new Error("Server error");

        const data = await res.json();

        if (data.label === "phishing") {
            resultDiv.innerHTML = `
                            <div class="warning-header">
                                <div class="warning-icon">⚠️</div>
                                <div style="font-size: 18px; font-weight: 600; color:red;">SITUS PHISING TERDETEKSI!</div>
                            </div>
                            
                            <div class="message">Model XGBoost mengidentifikasi situs ini sebagai phishing. Hindari memasukkan informasi pribadi.</div>
                        `;
        } else {
            resultDiv.innerHTML = `
                            <div class="warning-header">
                                <div class="warning-icon">✅</div>
                                <div style="font-size: 18px; font-weight: 600;">Situs Aman Terdeteksi</div>
                            </div>
                            <div class="message">Model XGBoost mengidentifikasi situs ini sebagai aman.</div>
                        `;
        }

        displayAnalysisDetails(features);
        viewBtn.classList.remove("hidden");
        closeBtn.classList.remove("hidden");
    } catch (err) {
        console.error(err);
        resultDiv.innerHTML = "Gagal terhubung ke server";
    }
});

document.getElementById("viewDetailsBtn").addEventListener("click", () => {
    const details = document.getElementById("analysisDetails");
    details.classList.toggle("hidden");
});

document.getElementById("closeBtn").addEventListener("click", () => {
    document.getElementById("result").classList.add("hidden");
    document.getElementById("analysisDetails").classList.add("hidden");
    document.getElementById("viewDetailsBtn").classList.add("hidden");
    document.getElementById("closeBtn").classList.add("hidden");
});
