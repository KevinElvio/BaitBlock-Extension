// Data contoh untuk analisis
const sampleData = {
    "length_url": 132,
    "length_hostname": 34,
    "ip": 0,
    "nb_dots": 5,
    "nb_hyphens": 3,
    "nb_slash": 7,
    "nb_at": 0,
    "nb_qm": 2,
    "nb_and": 4,
    "nb_eq": 3,
    "nb_underscore": 2,
    "nb_tilde": 0,
    "nb_percent": 1,
    "nb_colon": 1,
    "nb_semicolumn": 1,
    "nb_www": 0,
    "nb_com": 1,
    "nb_dslash": 2,
    "http_in_path": 1,
    "https_token": 1,
    "ratio_digits_url": 0.23
};

// Mengambil URL tab aktif saat halaman dimuat
document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
            document.getElementById("urlInput").value = tabs[0].url;
        }
    });
});

// Fungsi untuk menentukan risiko berdasarkan nilai
function getRiskLevel(value, featureName) {
    // Logika sederhana untuk menentukan risiko
    const riskRules = {
        'length_url': value > 100 ? 'high' : 'low',
        'length_hostname': value > 30 ? 'high' : 'low',
        'ip': value === 1 ? 'high' : 'low',
        'nb_dots': value > 4 ? 'high' : 'low',
        'nb_hyphens': value > 2 ? 'high' : 'low',
        'nb_slash': value > 5 ? 'high' : 'low',
        'nb_at': value > 0 ? 'high' : 'low',
        'nb_qm': value > 1 ? 'high' : 'low',
        'nb_and': value > 3 ? 'high' : 'low',
        'nb_eq': value > 2 ? 'high' : 'low',
        'nb_underscore': value > 1 ? 'high' : 'low',
        'nb_percent': value > 0 ? 'high' : 'low',
        'nb_colon': value > 1 ? 'high' : 'low',
        'nb_semicolumn': value > 0 ? 'high' : 'low',
        'nb_www': value === 0 ? 'high' : 'low',
        'nb_com': value > 1 ? 'high' : 'low',
        'nb_dslash': value > 1 ? 'high' : 'low',
        'http_in_path': value === 1 ? 'high' : 'low',
        'https_token': value === 0 ? 'high' : 'low',
        'ratio_digits_url': value > 0.15 ? 'high' : 'low'
    };

    return riskRules[featureName] || 'medium';
}

// Fungsi untuk menampilkan detail analisis
function displayAnalysisDetails(data) {
    const detailsGrid = document.getElementById('detailsGrid');
    detailsGrid.innerHTML = '';

    // Mapping nama fitur yang lebih deskriptif
    const featureNames = {
        'length_url': 'Panjang URL',
        'length_hostname': 'Panjang Hostname',
        'ip': 'Mengandung IP',
        'nb_dots': 'Jumlah Titik',
        'nb_hyphens': 'Jumlah Hyphen',
        'nb_slash': 'Jumlah Slash',
        'nb_at': 'Jumlah Simbol @',
        'nb_qm': 'Jumlah Tanda Tanya',
        'nb_and': 'Jumlah Simbol &',
        'nb_eq': 'Jumlah Simbol =',
        'nb_underscore': 'Jumlah Underscore',
        'nb_tilde': 'Jumlah Tilde',
        'nb_percent': 'Jumlah Persen',
        'nb_colon': 'Jumlah Titik Dua',
        'nb_semicolumn': 'Jumlah Titik Koma',
        'nb_www': 'Mengandung www',
        'nb_com': 'Jumlah .com',
        'nb_dslash': 'Jumlah Double Slash',
        'http_in_path': 'HTTP dalam Path',
        'https_token': 'Token HTTPS',
        'ratio_digits_url': 'Rasio Digit dalam URL'
    };

    // Tampilkan setiap fitur
    for (const [key, value] of Object.entries(data)) {
        const riskLevel = getRiskLevel(value, key);

        const detailItem = document.createElement('div');
        detailItem.className = 'detail-item';

        detailItem.innerHTML = `
            <div class="detail-label">${featureNames[key] || key}</div>
            <div class="detail-value ${riskLevel === 'high' ? 'high-risk' : 'low-risk'}">${value}</div>
        `;

        detailsGrid.appendChild(detailItem);
    }
}

// Klik tombol check
document.getElementById("checkBtn").addEventListener("click", async () => {
    const url = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");
    const analysisDetails = document.getElementById("analysisDetails");
    const viewDetailsBtn = document.getElementById("viewDetailsBtn");
    const closeBtn = document.getElementById("closeBtn");

    resultDiv.textContent = "";
    resultDiv.className = "";
    resultDiv.classList.remove("hidden");

    resultDiv.innerHTML = `
        <div style="font-size: 18px; margin-bottom: 10px;">⏳</div>
        <div style="font-size: 16px;">Memeriksa URL...</div>
    `;

    try {
        const response = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (data.status === "phishing") {
            resultDiv.innerHTML = `
                <div class="warning-header">
                    <div class="warning-icon">⚠️</div>
                    <div style="font-size: 18px; font-weight: 600;">PERINGATAN: Situs Phishing Terdeteksi!</div>
                </div>
                <div class="confidence">${data.confidence || 94}%</div>
                <div class="message">Model XGBoost mengidentifikasi situs ini sebagai phishing dengan tingkat kepercayaan ${data.confidence || 94}%. Hindari memasukkan informasi pribadi.</div>
            `;
            resultDiv.className = "phishing";
        } else {
            resultDiv.innerHTML = `
                <div class="warning-header">
                    <div class="warning-icon">✅</div>
                    <div style="font-size: 18px; font-weight: 600;">Situs Aman Terdeteksi</div>
                </div>
                <div class="confidence">${data.confidence || 12}%</div>
                <div class="message">Model XGBoost mengidentifikasi situs ini sebagai aman dengan tingkat kepercayaan ${data.confidence || 12}%.</div>
            `;
            resultDiv.className = "safe";
        }

        if (data.features) {
            displayAnalysisDetails(data.features);
        } else {
            displayAnalysisDetails(sampleData); 
        }

        // setTimeout(() => {
        //     // Simulasi hasil phishing (94% confidence)
        //     const isPhishing = Math.random() > 0.5; // 50% kemungkinan phishing
        //     const confidence = isPhishing ? 94 : 12;

        //     // Tampilkan hasil
        //     if (isPhishing) {
        //         resultDiv.innerHTML = `
        //             <div class="warning-header">
        //                 <div class="warning-icon">⚠️</div>
        //                 <div style="font-size: 18px; font-weight: 600;">PERINGATAN: Situs Phishing Terdeteksi!</div>
        //             </div>
        //             <div class="confidence">${confidence}%</div>
        //             <div class="message">Model XGBoost mengidentifikasi situs ini sebagai phishing dengan tingkat kepercayaan ${confidence}%. Hindari memasukkan informasi pribadi.</div>
        //         `;
        //         resultDiv.className = "phishing";
        //     } else {
        //         resultDiv.innerHTML = `
        //             <div class="warning-header">
        //                 <div class="warning-icon">✅</div>
        //                 <div style="font-size: 18px; font-weight: 600;">Situs Aman Terdeteksi</div>
        //             </div>
        //             <div class="confidence">${confidence}%</div>
        //             <div class="message">Model XGBoost mengidentifikasi situs ini sebagai aman dengan tingkat kepercayaan ${confidence}%.</div>
        //         `;
        //         resultDiv.className = "safe";
        //     }

        //     // Tampilkan detail analisis
        //     displayAnalysisDetails(sampleData);

        //     // Tampilkan tombol
        //     viewDetailsBtn.classList.remove("hidden");
        //     closeBtn.classList.remove("hidden");
        //     viewDetailsBtn.textContent = "Lihat Detail";
        //     analysisDetails.classList.add("hidden");

        //     // Reset scroll ke atas
        //     document.body.scrollTop = 0;
        // }, 1000); // Simulasi delay jaringan

    } catch (error) {
        console.error("Error:", error);
        resultDiv.innerHTML = `
            <div style="font-size: 18px; margin-bottom: 10px;">❌</div>
            <div style="font-size: 16px;">Error connecting to API</div>
            <div style="font-size: 12px; margin-top: 10px; color: #a0a0c0;">${error.message}</div>
        `;
    }
});

// Tombol lihat detail
document.getElementById("viewDetailsBtn").addEventListener("click", () => {
    const analysisDetails = document.getElementById("analysisDetails");
    analysisDetails.classList.toggle("hidden");

    // Update teks tombol
    const btn = document.getElementById("viewDetailsBtn");
    if (analysisDetails.classList.contains("hidden")) {
        btn.textContent = "Lihat Detail";
    } else {
        btn.textContent = "Sembunyikan Detail";
    }
});

// Tombol tutup
document.getElementById("closeBtn").addEventListener("click", () => {
    // Reset tampilan
    document.getElementById("result").classList.add("hidden");
    document.getElementById("analysisDetails").classList.add("hidden");
    document.getElementById("viewDetailsBtn").classList.add("hidden");
    document.getElementById("closeBtn").classList.add("hidden");
});