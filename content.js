// content.js - Ekstraksi Fitur DOM untuk BaitBlock (sesuai 81 fitur endpoint)
// File ini berjalan di konteks halaman web (context: page) dan mengumpulkan
// fitur-fitur DOM yang digunakan untuk mendeteksi website phishing.

(function() {
  'use strict';

  console.log('BaitBlock content.js loaded on:', window.location.href);

  // Fungsi utama untuk mengekstraksi 23 fitur DOM dari halaman web
  // Fitur-fitur ini disesuaikan dengan fitur yang digunakan model ML deteksi phishing
  function extractDOMFeatures() {
    // Inisialisasi objek fitur dengan nilai default 0
    const features = {
      nb_hyperlinks: 0,           // Jumlah total hyperlink di halaman
      ratio_intHyperlinks: 0,     // Rasio hyperlink internal (domain sama)
      ratio_extHyperlinks: 0,    // Rasio hyperlink eksternal (domain berbeda)
      ratio_nullHyperlinks: 0,   // Rasio hyperlink null/kosong (#, javascript:)
      nb_extCSS: 0,               // Jumlah CSS eksternal yang dimuat
      ratio_intRedirection: 0,  // Rasio pengalihan internal (estimasi)
      ratio_extRedirection: 0,   // Rasio pengalihan eksternal (estimasi)
      ratio_intErrors: 0,        // Rasio error internal (estimasi)
      ratio_extErrors: 0,        // Rasio error eksternal (estimasi)
      login_form: 0,             // Apakah ada form login (input password)
      external_favicon: 0,       // Apakah favicon dari domain eksternal
      links_in_tags: 0,          // Jumlah link di dalam tag script/style
      submit_email: 0,           // Apakah ada input email untuk submit
      ratio_intMedia: 0,        // Rasio media internal (gambar/video/audio)
      ratio_extMedia: 0,         // Rasio media eksternal
      sfh: 0,                    // Server Form Handler kosong (form tanpa action)
      iframe: 0,                 // Apakah halaman menggunakan iframe
      popup_window: 0,           // Apakah ada link yang membuka popup
      safe_anchor: 0,            // Jumlah anchor aman (#, javascript:, nofollow)
      onmouseover: 0,            // Apakah ada elemen dengan onmouseover
      right_clic: 0,             // Apakah klik kanan dinonaktifkan
      empty_title: 0,            // Apakah title halaman kosong
      domain_in_title: 0,         // Apakah domain ada di title halaman
      domain_with_copyright: 0    // Apakah ada copyright dengan nama domain
    };

    try {
      // Ambil hostname dan URL halaman saat ini (lowercase untuk perbandingan)
      const hostname = window.location.hostname.toLowerCase();
      const pageUrl = window.location.href.toLowerCase();

      // === Hyperlinks ===
      // Ekstraksi semua hyperlink (<a href>) dan kategorikan berdasarkan jenisnya
      const links = document.querySelectorAll('a[href]');
      features.nb_hyperlinks = links.length;

      let internalLinks = 0;   // Link internal (domain sama)
      let externalLinks = 0;   // Link eksternal (domain berbeda)
      let nullLinks = 0;        // Link null/kosong

      // Loop setiap link untuk klasifikasi
      links.forEach(link => {
        const href = link.getAttribute('href') || '';

        // Kategori null: href kosong, '#', 'javascript:void(0)', atau 'javascript:;'
        if (href === '' || href === '#' || href === 'javascript:void(0)' || href === 'javascript:;') {
          nullLinks++;
        } else if (href.startsWith('http')) {
          // Link dengan protokol http/https
          try {
            const linkHostname = new URL(href).hostname.toLowerCase();
            // Bandingkan hostname dengan hostname halaman saat ini
            if (linkHostname === hostname || pageUrl.includes(linkHostname)) {
              internalLinks++;
            } else {
              externalLinks++;
            }
          } catch (e) {
            externalLinks++;
          }
        } else if (href.startsWith('/') || href.startsWith('./') || href.startsWith('../')) {
          // Link relatif (path dimulai dengan /, ./, atau ../)
          internalLinks++;
        } else {
          // Link lain dianggap internal
          internalLinks++;
        }
      });

      // Hitung rasio masing-masing jenis link
      const totalLinks = internalLinks + externalLinks + nullLinks;
      if (totalLinks > 0) {
        features.ratio_intHyperlinks = internalLinks / totalLinks;
        features.ratio_extHyperlinks = externalLinks / totalLinks;
        features.ratio_nullHyperlinks = nullLinks / totalLinks;
      }

      // === External CSS ===
      // Hitung jumlah file CSS yang dimuat dari domain eksternal
      const cssLinks = document.querySelectorAll('link[rel="stylesheet"][href]');
      features.nb_extCSS = Array.from(cssLinks).filter(link => {
        const href = link.getAttribute('href') || '';
        return href.startsWith('http') && !href.includes(hostname);
      }).length;

      // === Media ===
      // Ekstraksi media (img, video, audio, source) dan kategorikan
      const mediaElements = document.querySelectorAll('img, video, audio, source');
      let intMedia = 0;
      let extMedia = 0;

      mediaElements.forEach(el => {
        const src = el.src || el.getAttribute('data-src') || '';
        if (src.startsWith('http')) {
          try {
            const srcHostname = new URL(src).hostname.toLowerCase();
            if (srcHostname === hostname) {
              intMedia++;
            } else {
              extMedia++;
            }
          } catch (e) {
            extMedia++;
          }
        }
      });

      const totalMedia = intMedia + extMedia;
      if (totalMedia > 0) {
        features.ratio_intMedia = intMedia / totalMedia;
        features.ratio_extMedia = extMedia / totalMedia;
      }

      // === Links in Tags ===
      // Deteksi apakah ada href atau src di dalam tag script atau style
      // (Biasanya mencurigakan - phishing sering menyembunyikan link di sini)
      const scripts = document.querySelectorAll('script, style');
      const linksInScripts = Array.from(scripts).filter(s => {
        const text = s.textContent || '';
        return /href\s*=/i.test(text) || /src\s*=/i.test(text);
      }).length;
      features.links_in_tags = linksInScripts;

      // === Login Form ===
      // Deteksi apakah halaman memiliki form login
      // Cek input dengan type="password" atau input dengan name/id mengandung "pass"
      const passwordFields = document.querySelectorAll('input[type="password"]');
      if (passwordFields.length > 0) {
        features.login_form = 1;
      } else {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
          const inputs = form.querySelectorAll('input');
          inputs.forEach(input => {
            const name = (input.name || '').toLowerCase();
            const id = (input.id || '').toLowerCase();
            if (name.includes('pass') || id.includes('pass')) {
              features.login_form = 1;
            }
          });
        });
      }

      // === Submit Email ===
      // Deteksi apakah ada input email untuk subscribe/submit
      const emailInputs = document.querySelectorAll('input[type="email"]');
      if (emailInputs.length > 0) {
        features.submit_email = 1;
      }

      // === SFH (Server Form Handler) ===
      // Deteksi form dengan action kosong atau mencurigakan
      // Phishing sering menggunakan form tanpa action untuk menyembunyikan submit URL
      const forms = document.querySelectorAll('form[action]');
      let emptyActionForms = 0;
      forms.forEach(form => {
        const action = form.getAttribute('action') || '';
        if (action === '' || action === '#' || action === 'about:blank') {
          emptyActionForms++;
        }
      });
      features.sfh = emptyActionForms > 0 ? 1 : 0;

      // === External Favicon ===
      // Deteksi apakah favicon dimuat dari domain eksternal
      // Indikasi bahwa halaman mungkin bukan milik resmi domain
      const favicon = document.querySelector('link[rel*="icon"]');
      if (favicon) {
        const href = favicon.getAttribute('href') || '';
        if (href.startsWith('http') && !href.includes(hostname)) {
          features.external_favicon = 1;
        }
      }

      // === Iframe ===
      // Deteksi apakah halaman menggunakan iframe
      // Phishing sering menggunakan iframe tersembunyi untuk menutupi konten
      const iframes = document.querySelectorAll('iframe');
      if (iframes.length > 0) {
        features.iframe = 1;
      }

      // === Popup Window ===
      // Deteksi apakah ada link yang membuka popup (window.open atau target="_blank")
      // Teknik phishing sering menggunakan popup untuk menipu pengguna
      const popupLinks = document.querySelectorAll('[onclick*="window.open"], [target="_blank"]');
      features.popup_window = popupLinks.length > 0 ? 1 : 0;

      // === Safe Anchor ===
      // Hitung jumlah anchor yang "aman" (menggunakan #, javascript, atau rel="nofollow")
      // Link mencurigakan biasanya tidak menggunakan ini
      const safeAnchors = Array.from(links).filter(link => {
        const href = link.getAttribute('href') || '';
        const rel = link.getAttribute('rel') || '';
        return href.startsWith('#') || href.startsWith('javascript') || rel.includes('nofollow');
      }).length;
      features.safe_anchor = safeAnchors;

      // === OnMouseOver ===
      // Deteksi apakah ada elemen dengan atribut onmouseover
      // Phishing sering menggunakan ini untuk menyembunyikan URL asli saat hover
      const elementsWithMouseover = document.querySelectorAll('[onmouseover]');
      if (elementsWithMouseover.length > 0) {
        features.onmouseover = 1;
      }

      // === Right Click (disable) ===
      // Deteksi apakah klik kanan dinonaktifkan (ondragstart atau oncontextmenu)
      // Phishing sering menonaktifkan right-click untuk mencegah copy paste
      const body = document.body;
      if (body && (body.ondragstart !== null || body.oncontextmenu !== null)) {
        features.right_clic = 1;
      }
      document.querySelectorAll('*').forEach(el => {
        if (el.ondragstart !== null || el.oncontextmenu !== null) {
          features.right_clic = 1;
        }
      });

      // === Empty Title ===
      // Deteksi apakah title halaman kosong
      // Website resmi biasanya memiliki title yang jelas
      const pageTitle = document.title || '';
      features.empty_title = pageTitle.trim() === '' ? 1 : 0;

      // === Domain in Title ===
      // Deteksi apakah hostname domain ada di dalam title halaman
      // Website resmi biasanya mencantumkan nama domain di title
      if (pageTitle.toLowerCase().includes(hostname)) {
        features.domain_in_title = 1;
      }

      // === Domain with Copyright ===
      // Deteksi apakah ada teks copyright yang mencantumkan nama domain
      // Indikasi bahwa website adalah milik sah dari domain tersebut
      const pageText = document.body ? document.body.innerText.toLowerCase() : '';
      const copyrightMatch = pageText.includes('copyright') && pageText.includes(hostname.split('.').slice(-2).join('.'));
      features.domain_with_copyright = copyrightMatch ? 1 : 0;

      // === Redirects and Errors (estimation) ===
      // Catatan: Fitur ini memerlukan request jaringan yang tidak bisa dilakukan
      // dari content script karena keterbatasan CORS dan permissions
      // Nilai default 0 diberikan - bisa diperluas dengan background script
      features.ratio_intRedirection = 0;
      features.ratio_extRedirection = 0;
      features.ratio_intErrors = 0;
      features.ratio_extErrors = 0;

    } catch (error) {
      console.error('BaitBlock: Error extracting DOM features:', error);
    }

    return features;
  }

  // === Message Listener ===
  // Mendengarkan pesan dari background script atau popup
  // Saat menerima request 'getDOMFeatures', jalankan ekstraksi dan return hasilnya
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'getDOMFeatures') {
      const features = extractDOMFeatures();
      sendResponse(features);
    }
    return true; // indicate async response
  });

})();