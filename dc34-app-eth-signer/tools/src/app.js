/* ===================== UR Bridge application ===================== */
/* Wires the URLib library, jsQR / BarcodeDetector and qrcode-generator
 * into the three views: Scan (camera -> URDecoder), Display (re-encode
 * as static QR parts for a slow hardware-wallet camera), Vectors. */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  /* ---------------- tabs ---------------- */
  var views = { scan: $('view-scan'), display: $('view-display'), vectors: $('view-vectors') };
  var tabs = { scan: $('tab-scan'), display: $('tab-display'), vectors: $('tab-vectors') };
  function showView(name) {
    Object.keys(views).forEach(function (k) {
      views[k].classList.toggle('active', k === name);
      tabs[k].classList.toggle('active', k === name);
    });
    if (name !== 'scan') stopCamera();
  }
  tabs.scan.onclick = function () { showView('scan'); };
  tabs.display.onclick = function () { showView('display'); };
  tabs.vectors.onclick = function () { showView('vectors'); };

  /* ---------------- decode engine selection ---------------- */
  var barcodeDetector = null;
  var engineName = 'jsQR';
  if (typeof window.BarcodeDetector === 'function') {
    try {
      barcodeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
      engineName = 'BarcodeDetector';
    } catch (e) { barcodeDetector = null; }
  }
  $('footer').textContent = 'decode engine: ' + engineName +
    (barcodeDetector ? ' (native)' : ' (js fallback)');

  /* ================================================================
   * SCAN view
   * ================================================================ */
  var decoder = new URLib.URDecoder();
  var video = $('video');
  var stream = null;
  var scanTimer = null;
  var scanCanvas = document.createElement('canvas');
  var scanCtx = scanCanvas.getContext('2d', { willReadFrequently: true });
  var lastText = null; // avoid re-feeding the identical frame text

  function resetDecoder() {
    decoder = new URLib.URDecoder();
    lastText = null;
    $('scan-type').textContent = '–';
    $('scan-log').textContent = '';
    $('scan-result').style.display = 'none';
    updateProgress();
  }

  function updateProgress() {
    var got = decoder.receivedPartIndexes ? decoder.receivedPartIndexes.size : 0;
    var total = decoder.expectedPartCount;
    var pct = Math.round(decoder.estimatedPercentComplete() * 100);
    $('scan-parts').textContent = 'parts ' + got + '/' + (total === null ? '?' : total);
    $('scan-pct').textContent = pct + '%';
    $('progress-inner').style.width =
      (total ? Math.round(100 * got / total) : 0) + '%';
    if (decoder.expectedType) $('scan-type').textContent = decoder.expectedType;
  }

  function logLine(msg) {
    $('scan-log').textContent = msg;
  }

  // Feed one decoded QR text into the UR decoder; updates all UI state.
  function feedText(text) {
    if (decoder.isComplete() || decoder.isFailure()) return false;
    if (text === lastText) return false;
    lastText = text;
    var accepted = decoder.receivePart(text);
    if (!accepted) return false;
    if (decoder.lastPartWasMixed) {
      var idx = Array.from(decoder.lastPartIndexes).sort(function (a, b) { return a - b; });
      logLine('mixed part received: fragments [' + idx.join(', ') + ']');
    } else if (decoder.lastPartIndexes) {
      var one = decoder.lastPartIndexes.values().next().value;
      logLine('pure part received: fragment ' + one);
    }
    updateProgress();
    if (decoder.isFailure()) {
      logLine('DECODE FAILED: ' + decoder.resultError);
    } else if (decoder.isComplete()) {
      onScanComplete();
    }
    return true;
  }

  function onScanComplete() {
    stopCamera();
    var msg = decoder.resultMessage();
    $('result-type').textContent = decoder.resultType;
    $('result-len').textContent = msg.length;
    $('result-hex').textContent = URLib.bytesToHex(msg);
    $('scan-result').style.display = 'block';
    logLine('complete');
  }

  /* ---- camera ---- */
  function startCamera() {
    $('camera-error').style.display = 'none';
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      cameraFailed('Camera API unavailable. Browsers only allow the camera on https:// pages, ' +
        'localhost, or (in Chrome) file:// URLs. Use the photo or paste fallbacks below.');
      return;
    }
    navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false
    }).then(function (s) {
      stream = s;
      video.srcObject = s;
      video.play();
      $('btn-camera').textContent = 'Stop camera';
      // Poll frames at ~10fps
      scanTimer = setInterval(scanFrame, 100);
    }).catch(function (err) {
      cameraFailed('Camera access failed (' + err.name + '). ' +
        'The camera needs a secure context (https://, localhost, or Chrome file://) ' +
        'and permission. Use the photo or paste fallbacks below.');
    });
  }

  function stopCamera() {
    if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
    if (stream) {
      stream.getTracks().forEach(function (t) { t.stop(); });
      stream = null;
      video.srcObject = null;
    }
    $('btn-camera').textContent = 'Start camera';
  }

  function cameraFailed(msg) {
    var el = $('camera-error');
    el.textContent = msg;
    el.style.display = 'block';
  }

  $('btn-camera').onclick = function () {
    if (stream) stopCamera(); else startCamera();
  };

  function scanFrame() {
    if (!stream || video.readyState < 2) return;
    if (barcodeDetector) {
      barcodeDetector.detect(video).then(function (codes) {
        if (codes.length) feedText(codes[0].rawValue);
      }).catch(function () { /* transient detect errors are fine */ });
    } else {
      var w = video.videoWidth, h = video.videoHeight;
      if (!w || !h) return;
      // Downscale big frames for jsQR speed
      var scale = Math.min(1, 800 / Math.max(w, h));
      scanCanvas.width = Math.round(w * scale);
      scanCanvas.height = Math.round(h * scale);
      scanCtx.drawImage(video, 0, 0, scanCanvas.width, scanCanvas.height);
      var img = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
      var code = jsQR(img.data, img.width, img.height, { inversionAttempts: 'dontInvert' });
      if (code && code.data) feedText(code.data);
    }
  }

  /* ---- photo fallback ---- */
  $('file-input').onchange = function () {
    var file = this.files && this.files[0];
    if (!file) return;
    $('file-status').textContent = 'decoding photo…';
    var url = URL.createObjectURL(file);
    var im = new Image();
    im.onload = function () {
      URL.revokeObjectURL(url);
      var scale = Math.min(1, 1200 / Math.max(im.width, im.height));
      scanCanvas.width = Math.round(im.width * scale);
      scanCanvas.height = Math.round(im.height * scale);
      scanCtx.drawImage(im, 0, 0, scanCanvas.width, scanCanvas.height);
      var img = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
      var code = jsQR(img.data, img.width, img.height);
      if (code && code.data) {
        lastText = null; // photos may legitimately repeat
        var ok = feedText(code.data);
        $('file-status').textContent = ok ? 'part accepted' : 'QR found but part rejected (wrong type / duplicate?)';
      } else {
        $('file-status').textContent = 'no QR code found in photo';
      }
    };
    im.onerror = function () { $('file-status').textContent = 'could not read image'; };
    im.src = url;
  };

  /* ---- paste fallback ---- */
  $('btn-add-parts').onclick = function () {
    var lines = $('paste-parts').value.split('\n')
      .map(function (l) { return l.trim(); })
      .filter(function (l) { return l.length; });
    var accepted = 0;
    lines.forEach(function (l) {
      lastText = null;
      if (feedText(l)) accepted++;
    });
    $('paste-status').textContent = accepted + '/' + lines.length + ' parts accepted';
  };

  $('btn-scan-reset').onclick = resetDecoder;

  $('btn-to-display').onclick = function () {
    loadPayload(decoder.resultType, decoder.resultMessage(), 'scanned ' + decoder.resultType);
    showView('display');
  };

  /* ================================================================
   * DISPLAY view
   * ================================================================ */
  var payload = null;      // { type, cbor (Uint8Array), label }
  var parts = [];          // current UR part strings
  var partIndex = 0;
  var autoTimer = null;

  function loadPayload(type, cbor, label) {
    payload = { type: type, cbor: cbor, label: label };
    $('display-source').textContent = label + ' — ' + cbor.length + ' bytes CBOR';
    $('display-empty').style.display = 'none';
    $('display-main').style.display = 'block';
    regenerateParts();
  }

  function regenerateParts() {
    if (!payload) return;
    var fragSize = parseInt($('frag-size').value, 10);
    parts = URLib.urEncode(payload.type, payload.cbor, fragSize);
    partIndex = 0;
    renderPart();
  }

  function renderPart() {
    if (!parts.length) return;
    var text = parts[partIndex];
    var qr = qrcode(0, 'L'); // auto type number, error correction L
    // Uppercase UR strings fit the QR alphanumeric charset -> smaller QRs
    try {
      qr.addData(text, 'Alphanumeric');
      qr.make();
    } catch (e) {
      qr = qrcode(0, 'L');
      qr.addData(text, 'Byte');
      qr.make();
    }
    $('qr-card').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
    $('part-label').textContent = parts.length === 1
      ? 'Single part' : 'Part ' + (partIndex + 1) + ' of ' + parts.length;
    $('ur-text').textContent = text;
    $('btn-prev').disabled = parts.length === 1;
    $('btn-next').disabled = parts.length === 1;
  }

  function step(delta) {
    if (!parts.length) return;
    partIndex = (partIndex + delta + parts.length) % parts.length;
    renderPart();
  }

  $('btn-prev').onclick = function () { step(-1); };
  $('btn-next').onclick = function () { step(1); };
  $('frag-size').onchange = regenerateParts;

  $('auto-advance').onchange = function () {
    if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
    var ms = parseInt(this.value, 10);
    if (ms > 0) autoTimer = setInterval(function () { step(1); }, ms);
  };

  $('btn-manual-load').onclick = function () {
    var status = $('manual-status');
    status.style.display = 'none';
    try {
      var type = $('manual-type').value.trim().toLowerCase();
      if (!URLib.isURType(type)) throw new Error('invalid UR type (a-z, 0-9, hyphen)');
      var cbor = URLib.hexToBytes($('manual-hex').value);
      if (!cbor.length) throw new Error('empty CBOR hex');
      loadPayload(type, cbor, 'manual ' + type);
    } catch (e) {
      status.textContent = String(e.message || e);
      status.style.display = 'block';
    }
  };

  /* ================================================================
   * VECTORS view
   * ================================================================ */
  (function buildVectorTable() {
    var tbody = $('vectors-table').getElementsByTagName('tbody')[0];
    TEST_VECTORS.forEach(function (vec) {
      var tr = document.createElement('tr');
      function td(text) {
        var el = document.createElement('td');
        el.textContent = text;
        tr.appendChild(el);
        return el;
      }
      var name = td(vec.name);
      var d = document.createElement('div');
      d.className = 'hint';
      d.textContent = vec.description;
      name.appendChild(d);
      td(vec.urType);
      td((vec.cborHex.length / 2) + ' B');
      td(String(vec.parts.length));
      var action = document.createElement('td');
      var btn = document.createElement('button');
      btn.textContent = 'Load';
      btn.onclick = function () {
        loadPayload(vec.urType, URLib.hexToBytes(vec.cborHex), 'vector ' + vec.name);
        showView('display');
      };
      action.appendChild(btn);
      tr.appendChild(action);
      tbody.appendChild(tr);
    });
  })();

  $('btn-run-tests').onclick = function () {
    var out = $('test-results');
    out.innerHTML = '';
    $('test-summary').textContent = 'running…';
    // Let the UI paint before the (fast but synchronous) tests run
    setTimeout(function () {
      var res = URLib.selfTest(TEST_VECTORS, function (name, ok, detail) {
        var div = document.createElement('div');
        div.className = ok ? 'ok' : 'err';
        div.textContent = (ok ? 'PASS ' : 'FAIL ') + name + (detail ? ' — ' + detail : '');
        out.appendChild(div);
      });
      var sum = $('test-summary');
      if (res.failed === 0) {
        sum.innerHTML = '<span class="ok">All ' + res.passed + ' checks PASS</span>';
      } else {
        sum.innerHTML = '<span class="err">' + res.failed + ' FAILED</span>, ' + res.passed + ' passed';
      }
    }, 30);
  };

  /* ---- init ---- */
  resetDecoder();
})();
