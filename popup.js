chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
document.getElementById("urlInput").value = tabs[0].url;
});


// Klik tombol check
document.getElementById("checkBtn").addEventListener("click", async () => {
const url = document.getElementById("urlInput").value;
const resultDiv = document.getElementById("result");


resultDiv.textContent = "Checking...";


try {
const response = await fetch("http://127.0.0.1:5000/predict", {
method: "POST",
headers: {
"Content-Type": "application/json"
},
body: JSON.stringify({ url })
});


const data = await response.json();


if (data.status === "phishing") {
resultDiv.textContent = "⚠ PHISHING";
resultDiv.className = "phishing";
} else {
resultDiv.textContent = "✅ LEGITIMATE";
resultDiv.className = "safe";
}


} catch (error) {
resultDiv.textContent = "Error connecting to API";
}
});