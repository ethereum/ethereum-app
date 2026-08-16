/*
 * ur.js — BC-UR (Uniform Resources, ERC-4527 transport) library.
 *
 * A 1:1 JavaScript port of tools/urlib.py (validated against the official
 * bc-ur reference vectors) plus a full fountain decoder ported from
 * BlockchainCommons bc-ur fountain-decoder.cpp, so that true fountain
 * streams (parts with seqNum > seqLen, i.e. mixed parts) decode correctly.
 *
 * Plain ES6, no DOM, no async. Works inlined in a browser page and under
 * node (run `node ur.js` for the self-test).
 */
var URLib = (function () {
  'use strict';

  // ---------------------------------------------------------------------
  // Byte helpers
  // ---------------------------------------------------------------------

  function toBytes(x) {
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return new Uint8Array(x);
    if (typeof x === 'string') {
      // UTF-8 encode (test strings are ASCII, but be correct anyway)
      var out = [];
      for (var i = 0; i < x.length; i++) {
        var c = x.codePointAt(i);
        if (c > 0xFFFF) i++;
        if (c < 0x80) out.push(c);
        else if (c < 0x800) out.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
        else if (c < 0x10000) out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
        else out.push(0xF0 | (c >> 18), 0x80 | ((c >> 12) & 0x3F), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
      }
      return new Uint8Array(out);
    }
    throw new Error('cannot convert to bytes');
  }

  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s;
  }

  function hexToBytes(hex) {
    hex = hex.replace(/\s+/g, '');
    if (hex.length % 2 !== 0) throw new Error('odd-length hex');
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) {
      var v = parseInt(hex.substr(i * 2, 2), 16);
      if (isNaN(v)) throw new Error('bad hex');
      out[i] = v;
    }
    return out;
  }

  function concatBytes(list) {
    var total = 0, i;
    for (i = 0; i < list.length; i++) total += list[i].length;
    var out = new Uint8Array(total), off = 0;
    for (i = 0; i < list.length; i++) { out.set(list[i], off); off += list[i].length; }
    return out;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  // ---------------------------------------------------------------------
  // SHA-256 — synchronous pure-JS (WebCrypto is async; xoshiro seeding
  // must be synchronous, so we implement the digest ourselves).
  // ---------------------------------------------------------------------

  var SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function sha256(data) {
    var msg = toBytes(data);
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var len = msg.length;
    // Padding: 0x80, zeros, 64-bit big-endian bit length
    var padded = new Uint8Array(((len + 8) >> 6 << 6) + 64);
    padded.set(msg);
    padded[len] = 0x80;
    var bitLenHi = Math.floor(len / 0x20000000);
    var bitLenLo = (len << 3) >>> 0;
    var pl = padded.length;
    padded[pl - 8] = (bitLenHi >>> 24) & 0xFF;
    padded[pl - 7] = (bitLenHi >>> 16) & 0xFF;
    padded[pl - 6] = (bitLenHi >>> 8) & 0xFF;
    padded[pl - 5] = bitLenHi & 0xFF;
    padded[pl - 4] = (bitLenLo >>> 24) & 0xFF;
    padded[pl - 3] = (bitLenLo >>> 16) & 0xFF;
    padded[pl - 2] = (bitLenLo >>> 8) & 0xFF;
    padded[pl - 1] = bitLenLo & 0xFF;

    var w = new Array(64);
    for (var off = 0; off < pl; off += 64) {
      var i;
      for (i = 0; i < 16; i++) {
        var j = off + i * 4;
        w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) | (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
      }
      for (i = 16; i < 64; i++) {
        var s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
        var s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
        var ch = ((e & f) ^ (~e & g)) >>> 0;
        var t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
        var S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
        var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
        var t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
      h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }
    var out = new Uint8Array(32);
    for (var k = 0; k < 8; k++) {
      out[k * 4] = (h[k] >>> 24) & 0xFF;
      out[k * 4 + 1] = (h[k] >>> 16) & 0xFF;
      out[k * 4 + 2] = (h[k] >>> 8) & 0xFF;
      out[k * 4 + 3] = h[k] & 0xFF;
    }
    return out;

    function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }
  }

  // ---------------------------------------------------------------------
  // CRC32 (IEEE, reflected, poly 0xEDB88320) — same as zlib.crc32
  // ---------------------------------------------------------------------

  var CRC_TABLE = (function () {
    var t = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(data) {
    var b = toBytes(data);
    var c = 0xFFFFFFFF;
    for (var i = 0; i < b.length; i++) c = (CRC_TABLE[(c ^ b[i]) & 0xFF] ^ (c >>> 8)) >>> 0;
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  function crc32Bytes(data) {
    var c = crc32(data);
    return new Uint8Array([(c >>> 24) & 0xFF, (c >>> 16) & 0xFF, (c >>> 8) & 0xFF, c & 0xFF]);
  }

  // ---------------------------------------------------------------------
  // Bytewords (minimal style): each byte -> first+last letter of its word,
  // payload followed by a 4-byte big-endian CRC32 trailer.
  // ---------------------------------------------------------------------

  var BYTEWORDS =
    'ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzz' +
    'calmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordown' +
    'drawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflap' +
    'flewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhang' +
    'hardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoin' +
    'joltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegs' +
    'liarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknail' +
    'navyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose' +
    'puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilk' +
    'skewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinugly' +
    'undouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhen' +
    'whizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom';

  var MINIMAL = [];
  var MINIMAL_MAP = {};
  (function () {
    for (var i = 0; i < 256; i++) {
      var w = BYTEWORDS.substr(i * 4, 4);
      var m = w[0] + w[3];
      MINIMAL.push(m);
      MINIMAL_MAP[m] = i;
    }
  })();

  function bytewordsEncodeMinimal(payload) {
    var data = concatBytes([toBytes(payload), crc32Bytes(payload)]);
    var s = '';
    for (var i = 0; i < data.length; i++) s += MINIMAL[data[i]];
    return s;
  }

  function bytewordsDecodeMinimal(s) {
    if (s.length % 2 !== 0 || s.length < 10) throw new Error('invalid bytewords length');
    var data = new Uint8Array(s.length / 2);
    for (var i = 0; i < data.length; i++) {
      var v = MINIMAL_MAP[s.substr(i * 2, 2)];
      if (v === undefined) throw new Error('invalid byteword: ' + s.substr(i * 2, 2));
      data[i] = v;
    }
    var body = data.subarray(0, data.length - 4);
    var checksum = data.subarray(data.length - 4);
    if (!bytesEqual(crc32Bytes(body), checksum)) throw new Error('bytewords checksum mismatch');
    // Return a copy so callers can keep it independently of `data`
    return new Uint8Array(body);
  }

  // ---------------------------------------------------------------------
  // Xoshiro256** seeded with SHA-256 of the seed material (bc-ur
  // convention). State words are big-endian per 8 digest bytes.
  // 64-bit arithmetic via BigInt.
  // ---------------------------------------------------------------------

  var MASK64 = (1n << 64n) - 1n;
  var POW2_64 = Math.pow(2, 64);

  function rotl64(x, k) {
    return ((x << k) | (x >> (64n - k))) & MASK64;
  }

  function Xoshiro256(seed) {
    var digest = sha256(seed);
    this.s = [];
    for (var i = 0; i < 4; i++) {
      var v = 0n;
      for (var j = 0; j < 8; j++) v = (v << 8n) | BigInt(digest[i * 8 + j]);
      this.s.push(v);
    }
  }

  Xoshiro256.prototype.next = function () {
    var s = this.s;
    var result = (rotl64((s[1] * 5n) & MASK64, 7n) * 9n) & MASK64;
    var t = (s[1] << 17n) & MASK64;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl64(s[3], 45n);
    return result;
  };

  Xoshiro256.prototype.nextDouble = function () {
    return Number(this.next()) / POW2_64;
  };

  Xoshiro256.prototype.nextInt = function (low, high) {
    return Math.floor(this.nextDouble() * (high - low + 1)) + low;
  };

  Xoshiro256.prototype.nextByte = function () { return this.nextInt(0, 255); };

  Xoshiro256.prototype.nextData = function (count) {
    var out = new Uint8Array(count);
    for (var i = 0; i < count; i++) out[i] = this.nextByte();
    return out;
  };

  // ---------------------------------------------------------------------
  // RandomSampler — Walker/Vose alias method, replicating bc-ur's
  // REVERSED index-order initialization loop.
  // ---------------------------------------------------------------------

  function RandomSampler(probs) {
    var n = probs.length;
    var total = 0, i;
    for (i = 0; i < n; i++) total += probs[i];
    var P = new Array(n);
    for (i = 0; i < n; i++) P[i] = probs[i] * n / total;
    var S = [], L = [];
    for (i = n - 1; i >= 0; i--) {
      (P[i] < 1 ? S : L).push(i);
    }
    var probsOut = new Array(n).fill(0);
    var aliases = new Array(n).fill(0);
    while (S.length && L.length) {
      var a = S.pop();
      var g = L.pop();
      probsOut[a] = P[a];
      aliases[a] = g;
      P[g] += P[a] - 1;
      (P[g] < 1 ? S : L).push(g);
    }
    while (L.length) probsOut[L.pop()] = 1;
    while (S.length) probsOut[S.pop()] = 1;
    this.probs = probsOut;
    this.aliases = aliases;
  }

  RandomSampler.prototype.next = function (rngDouble) {
    var r1 = rngDouble();
    var r2 = rngDouble();
    var i = Math.floor(this.probs.length * r1);
    return r2 < this.probs[i] ? i : this.aliases[i];
  };

  // ---------------------------------------------------------------------
  // Fountain helpers
  // ---------------------------------------------------------------------

  // Fisher-Yates style draw-without-replacement using nextInt(0, len-1)
  function shuffled(items, rng) {
    var remaining = items.slice();
    var result = [];
    while (remaining.length) {
      var index = rng.nextInt(0, remaining.length - 1);
      result.push(remaining.splice(index, 1)[0]);
    }
    return result;
  }

  function chooseDegree(seqLen, rng) {
    var probs = [];
    for (var i = 1; i <= seqLen; i++) probs.push(1.0 / i);
    var sampler = new RandomSampler(probs);
    return sampler.next(function () { return rng.nextDouble(); }) + 1;
  }

  // Set of fragment indexes mixed into part seqNum (1-based).
  function chooseFragments(seqNum, seqLen, checksum) {
    if (seqNum <= seqLen) return new Set([seqNum - 1]);
    // Seed = seqNum (4B BE) || checksum (4B BE)
    var seed = new Uint8Array(8);
    seed[0] = (seqNum >>> 24) & 0xFF; seed[1] = (seqNum >>> 16) & 0xFF;
    seed[2] = (seqNum >>> 8) & 0xFF; seed[3] = seqNum & 0xFF;
    seed[4] = (checksum >>> 24) & 0xFF; seed[5] = (checksum >>> 16) & 0xFF;
    seed[6] = (checksum >>> 8) & 0xFF; seed[7] = checksum & 0xFF;
    var rng = new Xoshiro256(seed);
    var degree = chooseDegree(seqLen, rng);
    var indexes = [];
    for (var i = 0; i < seqLen; i++) indexes.push(i);
    return new Set(shuffled(indexes, rng).slice(0, degree));
  }

  // ---------------------------------------------------------------------
  // Minimal CBOR (just what UR framing needs)
  // ---------------------------------------------------------------------

  function cborUint(n) {
    if (n < 0) throw new Error('negative uint');
    if (n < 24) return new Uint8Array([n]);
    if (n < 0x100) return new Uint8Array([24, n]);
    if (n < 0x10000) return new Uint8Array([25, (n >> 8) & 0xFF, n & 0xFF]);
    if (n < 0x100000000) {
      return new Uint8Array([26, (n >>> 24) & 0xFF, (n >>> 16) & 0xFF, (n >>> 8) & 0xFF, n & 0xFF]);
    }
    if (n <= Number.MAX_SAFE_INTEGER) {
      var hi = Math.floor(n / 0x100000000), lo = n % 0x100000000;
      return new Uint8Array([27,
        (hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF,
        (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF]);
    }
    throw new Error('uint too large');
  }

  function cborBytes(b) {
    b = toBytes(b);
    var header = cborUint(b.length);
    var out = new Uint8Array(header.length + b.length);
    out.set(header);
    out[0] |= 0x40;
    out.set(b, header.length);
    return out;
  }

  // Decoder for the fountain part: definite array(5)
  // [seqNum, seqLen, messageLen, checksum, data(bytes)] with any uint width.
  function decodeFountainPartCbor(cbor) {
    var pos = 0;
    function need(n) { if (pos + n > cbor.length) throw new Error('truncated CBOR'); }
    function readUintFor(ib) {
      var ai = ib & 0x1F;
      if (ai < 24) return ai;
      var n, v = 0, i;
      if (ai === 24) n = 1; else if (ai === 25) n = 2; else if (ai === 26) n = 4; else if (ai === 27) n = 8;
      else throw new Error('unsupported CBOR additional info ' + ai);
      need(n);
      for (i = 0; i < n; i++) v = v * 256 + cbor[pos + i];
      pos += n;
      if (v > Number.MAX_SAFE_INTEGER) throw new Error('uint too large');
      return v;
    }
    need(1);
    var head = cbor[pos++];
    if ((head >> 5) !== 4) throw new Error('not a CBOR array');
    var count = readUintFor(head);
    if (count !== 5) throw new Error('fountain part must be array(5)');
    var vals = [];
    for (var k = 0; k < 4; k++) {
      need(1);
      var ib = cbor[pos++];
      if ((ib >> 5) !== 0) throw new Error('expected uint in fountain part');
      vals.push(readUintFor(ib));
    }
    need(1);
    var bh = cbor[pos++];
    if ((bh >> 5) !== 2) throw new Error('expected byte string in fountain part');
    var blen = readUintFor(bh);
    need(blen);
    var data = new Uint8Array(cbor.subarray(pos, pos + blen));
    pos += blen;
    if (pos !== cbor.length) throw new Error('trailing bytes in fountain part');
    return { seqNum: vals[0], seqLen: vals[1], messageLen: vals[2], checksum: vals[3], data: data };
  }

  // ---------------------------------------------------------------------
  // UR encoder (pure parts only, like urlib.py's ur_encode)
  // ---------------------------------------------------------------------

  function findNominalFragmentLength(messageLen, minLen, maxLen) {
    var maxCount = Math.floor(messageLen / minLen);
    for (var fragmentCount = 1; fragmentCount <= maxCount; fragmentCount++) {
      var fragmentLen = Math.ceil(messageLen / fragmentCount);
      if (fragmentLen <= maxLen) return fragmentLen;
    }
    throw new Error('no valid fragment length');
  }

  function partitionMessage(message, fragmentLen) {
    var fragments = [];
    for (var i = 0; i < message.length; i += fragmentLen) {
      var frag = new Uint8Array(fragmentLen); // zero-padded
      frag.set(message.subarray(i, Math.min(i + fragmentLen, message.length)));
      fragments.push(frag);
    }
    return fragments;
  }

  function fountainPartCbor(seqNum, seqLen, messageLen, checksum, data) {
    // Note: checksum is always encoded as uint32 (0x1a + 4 bytes), matching
    // the reference implementation's framing.
    var ck = new Uint8Array([0x1a,
      (checksum >>> 24) & 0xFF, (checksum >>> 16) & 0xFF, (checksum >>> 8) & 0xFF, checksum & 0xFF]);
    return concatBytes([
      new Uint8Array([0x85]),
      cborUint(seqNum),
      cborUint(seqLen),
      cborUint(messageLen),
      ck,
      cborBytes(data)
    ]);
  }

  function isURType(type) {
    return /^[a-z0-9-]+$/.test(type);
  }

  // Returns array of uppercase UR part strings ("UR:TYPE/..." or
  // "UR:TYPE/K-N/..."). Single element if the message fits one part.
  function urEncode(urType, messageCbor, maxFragmentLen) {
    messageCbor = toBytes(messageCbor);
    if (maxFragmentLen == null || messageCbor.length <= maxFragmentLen) {
      return [('ur:' + urType + '/' + bytewordsEncodeMinimal(messageCbor)).toUpperCase()];
    }
    var fragmentLen = findNominalFragmentLength(messageCbor.length, 10, maxFragmentLen);
    var fragments = partitionMessage(messageCbor, fragmentLen);
    var checksum = crc32(messageCbor);
    var seqLen = fragments.length;
    var parts = [];
    for (var seqNum = 1; seqNum <= seqLen; seqNum++) { // pure parts only
      var part = fountainPartCbor(seqNum, seqLen, messageCbor.length, checksum, fragments[seqNum - 1]);
      parts.push(('ur:' + urType + '/' + seqNum + '-' + seqLen + '/' + bytewordsEncodeMinimal(part)).toUpperCase());
    }
    return parts;
  }

  // Any fountain part (including mixed ones beyond seqLen). Used by tests
  // to reproduce the reference multipart vectors.
  function fountainPartFor(urType, messageCbor, fragments, seqNum) {
    messageCbor = toBytes(messageCbor);
    var checksum = crc32(messageCbor);
    var seqLen = fragments.length;
    var indexes = chooseFragments(seqNum, seqLen, checksum);
    var mixed = new Uint8Array(fragments[0].length);
    indexes.forEach(function (i) {
      var frag = fragments[i];
      for (var j = 0; j < frag.length; j++) mixed[j] ^= frag[j];
    });
    var part = fountainPartCbor(seqNum, seqLen, messageCbor.length, checksum, mixed);
    return 'ur:' + urType + '/' + seqNum + '-' + seqLen + '/' + bytewordsEncodeMinimal(part);
  }

  // ---------------------------------------------------------------------
  // Fountain decoder — full port of bc-ur fountain-decoder.cpp:
  // handles simple parts, mixed-part reduction (XOR), and queued
  // processing, so streams from real wallets (seqNum > seqLen) decode.
  // ---------------------------------------------------------------------

  function setKey(indexSet) {
    return Array.from(indexSet).sort(function (a, b) { return a - b; }).join(',');
  }

  function isStrictSubset(sub, sup) {
    if (sub.size >= sup.size) return false;
    var ok = true;
    sub.forEach(function (v) { if (!sup.has(v)) ok = false; });
    return ok;
  }

  function setDifference(a, b) {
    var out = new Set();
    a.forEach(function (v) { if (!b.has(v)) out.add(v); });
    return out;
  }

  function xorWith(a, b) {
    var out = new Uint8Array(a.length);
    for (var i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function FountainDecoder() {
    this.receivedPartIndexes = new Set(); // pure fragment indexes obtained
    this.lastPartIndexes = null;          // indexes of the most recent part
    this.processedPartsCount = 0;
    this.result = null;                   // Uint8Array on success
    this.error = null;                    // string on failure
    this.expectedPartIndexes = null;      // Set(0..seqLen-1)
    this.expectedFragmentLen = null;
    this.expectedMessageLen = null;
    this.expectedChecksum = null;
    this._simpleParts = new Map();        // key -> {indexes, data}
    this._mixedParts = new Map();         // key -> {indexes, data}
    this._queuedParts = [];
  }

  FountainDecoder.prototype.expectedPartCount = function () {
    return this.expectedPartIndexes ? this.expectedPartIndexes.size : null;
  };

  FountainDecoder.prototype.isComplete = function () { return this.result !== null; };
  FountainDecoder.prototype.isFailure = function () { return this.error !== null; };

  FountainDecoder.prototype.estimatedPercentComplete = function () {
    if (this.isComplete()) return 1;
    if (this.expectedPartIndexes === null) return 0;
    var estimatedInputParts = this.expectedPartCount() * 1.75;
    return Math.min(0.99, this.processedPartsCount / estimatedInputParts);
  };

  // encoderPart: {seqNum, seqLen, messageLen, checksum, data}
  FountainDecoder.prototype.receivePart = function (encoderPart) {
    // Don't process the part if we're already done
    if (this.isComplete() || this.isFailure()) return false;

    // Don't continue if this part doesn't validate
    if (!this._validatePart(encoderPart)) return false;

    // Add this part to the queue
    var indexes = chooseFragments(encoderPart.seqNum, encoderPart.seqLen, encoderPart.checksum);
    var p = { indexes: indexes, data: encoderPart.data };
    this.lastPartIndexes = indexes;
    this._queuedParts.push(p);

    // Process the queue until we're done or the queue is empty
    while (!this.isComplete() && !this.isFailure() && this._queuedParts.length) {
      this._processQueueItem();
    }

    // Keep track of how many parts we've processed
    this.processedPartsCount += 1;
    return true;
  };

  FountainDecoder.prototype._validatePart = function (p) {
    if (this.expectedPartIndexes === null) {
      // First part: record what all subsequent parts must match.
      this.expectedPartIndexes = new Set();
      for (var i = 0; i < p.seqLen; i++) this.expectedPartIndexes.add(i);
      this.expectedMessageLen = p.messageLen;
      this.expectedChecksum = p.checksum;
      this.expectedFragmentLen = p.data.length;
      return true;
    }
    if (this.expectedPartCount() !== p.seqLen) return false;
    if (this.expectedMessageLen !== p.messageLen) return false;
    if (this.expectedChecksum !== p.checksum) return false;
    if (this.expectedFragmentLen !== p.data.length) return false;
    return true;
  };

  FountainDecoder.prototype._processQueueItem = function () {
    var part = this._queuedParts.shift();
    if (part.indexes.size === 1) {
      this._processSimplePart(part);
    } else {
      this._processMixedPart(part);
    }
  };

  FountainDecoder.prototype._reducePartByPart = function (a, b) {
    // If the fragments mixed into `b` are a strict (proper) subset of those
    // in `a`, the reduced part is (a - b) with data a XOR b.
    if (isStrictSubset(b.indexes, a.indexes)) {
      return { indexes: setDifference(a.indexes, b.indexes), data: xorWith(a.data, b.data) };
    }
    return a;
  };

  FountainDecoder.prototype._reduceMixedBy = function (p) {
    var self = this;
    var reducedParts = [];
    this._mixedParts.forEach(function (mp) {
      reducedParts.push(self._reducePartByPart(mp, p));
    });
    var newMixed = new Map();
    reducedParts.forEach(function (rp) {
      if (rp.indexes.size === 1) {
        self._queuedParts.push(rp);
      } else {
        newMixed.set(setKey(rp.indexes), rp);
      }
    });
    this._mixedParts = newMixed;
  };

  FountainDecoder.prototype._processSimplePart = function (p) {
    // Don't process duplicate parts
    var fragmentIndex = p.indexes.values().next().value;
    if (this.receivedPartIndexes.has(fragmentIndex)) return;

    // Record this part
    this._simpleParts.set(setKey(p.indexes), p);
    this.receivedPartIndexes.add(fragmentIndex);

    if (this.receivedPartIndexes.size === this.expectedPartCount()) {
      // Reassemble the message from its fragments, sorted by index
      var parts = Array.from(this._simpleParts.values());
      parts.sort(function (a, b) {
        return a.indexes.values().next().value - b.indexes.values().next().value;
      });
      var joined = concatBytes(parts.map(function (q) { return q.data; }));
      var message = joined.subarray(0, this.expectedMessageLen);
      // Verify the message checksum
      if (crc32(message) === this.expectedChecksum) {
        this.result = new Uint8Array(message);
      } else {
        this.error = 'invalid checksum';
      }
    } else {
      // Reduce all the mixed parts by this part
      this._reduceMixedBy(p);
    }
  };

  FountainDecoder.prototype._processMixedPart = function (p) {
    // Don't process duplicate parts
    if (this._mixedParts.has(setKey(p.indexes))) return;

    // Reduce this part by all the known simple and mixed parts
    var self = this;
    var p2 = p;
    this._simpleParts.forEach(function (r) { p2 = self._reducePartByPart(p2, r); });
    this._mixedParts.forEach(function (r) { p2 = self._reducePartByPart(p2, r); });

    if (p2.indexes.size === 1) {
      // Now simple: queue it
      this._queuedParts.push(p2);
    } else {
      // Reduce all the mixed parts by this one, then record it
      this._reduceMixedBy(p2);
      this._mixedParts.set(setKey(p2.indexes), p2);
    }
  };

  // ---------------------------------------------------------------------
  // UR decoder — port of bc-ur ur-decoder.cpp on top of FountainDecoder.
  // Accepts upper/lowercase part strings, tracks type consistency.
  // ---------------------------------------------------------------------

  function URDecoder() {
    this.expectedType = null;
    this.fountain = new FountainDecoder();
    this.resultType = null;
    this.resultError = null;
    this._result = null;       // Uint8Array message CBOR
    this.lastPartWasMixed = false;
    this.lastPartIndexes = null;
    this.receivedPartCount = 0; // count of accepted part strings
  }

  URDecoder.prototype._validateType = function (type) {
    if (this.expectedType === null) {
      if (!isURType(type)) return false;
      this.expectedType = type;
      return true;
    }
    return type === this.expectedType;
  };

  URDecoder.prototype.receivePart = function (s) {
    try {
      // Don't process the part if we're already done
      if (this.isComplete() || this.isFailure()) return false;

      var lowered = String(s).trim().toLowerCase();
      if (lowered.indexOf('ur:') !== 0) return false;
      var components = lowered.slice(3).split('/');
      if (components.length < 2) return false;

      var type = components[0];
      if (!isURType(type)) return false;
      if (!this._validateType(type)) return false;

      // Single-part UR: "ur:type/body" — we're done immediately.
      if (components.length === 2) {
        var body = bytewordsDecodeMinimal(components[1]);
        this._result = body;
        this.resultType = type;
        this.lastPartWasMixed = false;
        this.lastPartIndexes = new Set([0]);
        this.receivedPartCount += 1;
        return true;
      }

      // Multi-part URs must have exactly: type/seq/fragment
      if (components.length !== 3) return false;
      var seq = components[1];
      var fragment = components[2];

      var m = /^([0-9]+)-([0-9]+)$/.exec(seq);
      if (!m) return false;
      var seqNum = parseInt(m[1], 10);
      var seqLen = parseInt(m[2], 10);
      if (seqNum < 1 || seqLen < 1) return false;

      var cbor = bytewordsDecodeMinimal(fragment);
      var part = decodeFountainPartCbor(cbor);
      if (seqNum !== part.seqNum || seqLen !== part.seqLen) return false;

      if (!this.fountain.receivePart(part)) return false;

      this.receivedPartCount += 1;
      this.lastPartIndexes = this.fountain.lastPartIndexes;
      this.lastPartWasMixed = this.fountain.lastPartIndexes.size > 1;

      if (this.fountain.isComplete()) {
        this._result = this.fountain.result;
        this.resultType = type;
      } else if (this.fountain.isFailure()) {
        this.resultError = this.fountain.error;
      }
      return true;
    } catch (e) {
      return false;
    }
  };

  URDecoder.prototype.isComplete = function () { return this._result !== null; };
  URDecoder.prototype.isFailure = function () { return this.resultError !== null; };

  // Uint8Array of the message CBOR (length messageLen, CRC-verified)
  URDecoder.prototype.resultMessage = function () { return this._result; };

  Object.defineProperty(URDecoder.prototype, 'expectedPartCount', {
    get: function () {
      if (this._result !== null && this.fountain.expectedPartIndexes === null) return 1; // single-part
      return this.fountain.expectedPartCount();
    }
  });

  Object.defineProperty(URDecoder.prototype, 'receivedPartIndexes', {
    get: function () {
      if (this._result !== null && this.fountain.expectedPartIndexes === null) return new Set([0]);
      return this.fountain.receivedPartIndexes;
    }
  });

  URDecoder.prototype.estimatedPercentComplete = function () {
    if (this.isComplete()) return 1;
    return this.fountain.estimatedPercentComplete();
  };

  // ---------------------------------------------------------------------
  // Self-tests — every check from urlib.py self_test(), plus full
  // fountain-decoder tests and the ERC-4527 test vectors.
  //
  // `vectors` is the parsed content of test-vectors.json.
  // `report(name, ok, detail)` is called per check; returns {passed,failed}.
  // ---------------------------------------------------------------------

  function selfTest(vectors, report) {
    var passed = 0, failed = 0;
    function check(name, fn) {
      var ok = false, detail = '';
      try {
        var r = fn();
        ok = (r === undefined) ? true : !!r;
        if (!ok) detail = 'assertion returned false';
      } catch (e) {
        detail = String(e && e.message || e);
      }
      if (ok) passed++; else failed++;
      if (report) report(name, ok, detail);
    }
    function assertEq(got, want, what) {
      var g = JSON.stringify(got), w = JSON.stringify(want);
      if (g !== w) throw new Error((what || 'mismatch') + ': got ' + g + ' want ' + w);
    }

    check('sha256("abc")', function () {
      assertEq(bytesToHex(sha256('abc')),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    });

    check('crc32 vectors', function () {
      assertEq(crc32('Hello, world!'), 0xEBE6C6E6);
      assertEq(crc32('Wolf'), 0x598C84DC);
    });

    check('bytewords minimal encode/decode', function () {
      assertEq(bytewordsEncodeMinimal(new Uint8Array([0, 1, 2, 128, 255])), 'aeadaolazmjendeoti');
      assertEq(Array.from(bytewordsDecodeMinimal('aeadaolazmjendeoti')), [0, 1, 2, 128, 255]);
    });

    check('xoshiro256** "Wolf" first 12 (next()%100)', function () {
      var rng = new Xoshiro256('Wolf');
      var numbers = [];
      for (var i = 0; i < 100; i++) numbers.push(Number(rng.next() % 100n));
      assertEq(numbers.slice(0, 12), [42, 81, 85, 8, 82, 84, 76, 73, 70, 88, 2, 74]);
    });

    check('RandomSampler first 16 with probs [1,2,4,8]', function () {
      var rng = new Xoshiro256('Wolf');
      var sampler = new RandomSampler([1, 2, 4, 8]);
      var samples = [];
      for (var i = 0; i < 500; i++) samples.push(sampler.next(function () { return rng.nextDouble(); }));
      assertEq(samples.slice(0, 16), [3, 3, 3, 3, 3, 3, 3, 0, 2, 3, 3, 3, 3, 1, 2, 2]);
    });

    check('shuffled sequences', function () {
      var rng = new Xoshiro256('Wolf');
      var items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      var s1 = shuffled(items, rng);
      var s2 = shuffled(items, rng);
      assertEq(s1, [6, 4, 9, 3, 10, 5, 7, 8, 1, 2]);
      assertEq(s2, [10, 8, 6, 5, 1, 2, 3, 9, 7, 4]);
    });

    check('chooseFragments over make_message(1024)', function () {
      var message = new Xoshiro256('Wolf').nextData(1024);
      var checksum = crc32(message);
      var fragmentLen = findNominalFragmentLength(message.length, 10, 100);
      var fragments = partitionMessage(message, fragmentLen);
      var expected = [
        [0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [9],
        [2, 5, 6, 8, 9, 10], [8], [1, 5], [1], [0, 2, 4, 5, 8, 10], [5], [2], [2]
      ];
      for (var seqNum = 1; seqNum <= 20; seqNum++) {
        var got = Array.from(chooseFragments(seqNum, fragments.length, checksum))
          .sort(function (a, b) { return a - b; });
        assertEq(got, expected[seqNum - 1], 'seqNum ' + seqNum);
      }
    });

    var SINGLE_PART_50 =
      'ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch';

    check('single-part UR of make_message_ur(50)', function () {
      var msg50 = new Xoshiro256('Wolf').nextData(50);
      var parts = urEncode('bytes', cborBytes(msg50), null);
      assertEq(parts, [SINGLE_PART_50.toUpperCase()]);
    });

    // Reference multipart vectors: make_message_ur(256), max fragment 30
    var MULTIPART_REF = [
      'ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh',
      'ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz',
      'ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol',
      'ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas',
      'ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf',
      'ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp',
      'ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy',
      'ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk',
      'ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny',
      'ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs',
      'ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk',
      'ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs',
      'ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd',
      'ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt',
      'ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt'
    ];

    function makeMsg256Cbor() {
      return cborBytes(new Xoshiro256('Wolf').nextData(256));
    }
    function makeMsg256Fragments(messageCbor) {
      var fragmentLen = findNominalFragmentLength(messageCbor.length, 10, 30);
      return partitionMessage(messageCbor, fragmentLen);
    }

    check('multipart reference parts 1..15 (incl. mixed)', function () {
      var messageCbor = makeMsg256Cbor();
      var fragments = makeMsg256Fragments(messageCbor);
      for (var seqNum = 1; seqNum <= 15; seqNum++) {
        var got = fountainPartFor('bytes', messageCbor, fragments, seqNum);
        assertEq(got, MULTIPART_REF[seqNum - 1], 'seqNum ' + seqNum);
      }
    });

    check('urEncode pure parts match reference 1..9', function () {
      var messageCbor = makeMsg256Cbor();
      var parts = urEncode('bytes', messageCbor, 30);
      assertEq(parts.length, 9);
      for (var i = 0; i < 9; i++) assertEq(parts[i], MULTIPART_REF[i].toUpperCase(), 'part ' + (i + 1));
    });

    check('fountain decode: pure parts 1..9 in order', function () {
      var messageCbor = makeMsg256Cbor();
      var dec = new URDecoder();
      for (var i = 0; i < 9; i++) {
        if (!dec.receivePart(MULTIPART_REF[i])) throw new Error('part ' + (i + 1) + ' rejected');
      }
      if (!dec.isComplete()) throw new Error('not complete');
      assertEq(dec.resultType, 'bytes');
      assertEq(bytesToHex(dec.resultMessage()), bytesToHex(messageCbor));
      assertEq(dec.expectedPartCount, 9);
      assertEq(dec.receivedPartIndexes.size, 9);
    });

    check('fountain decode: adversarial mixed order (10..15 then 2,4,6,...)', function () {
      var messageCbor = makeMsg256Cbor();
      var fragments = makeMsg256Fragments(messageCbor);
      // Mixed parts first (seqNum 10..15 from the reference list), then a few
      // pure parts, then keep generating fountain parts until complete.
      var order = [10, 11, 12, 13, 14, 15, 2, 4, 6];
      var dec = new URDecoder();
      var i, fed = 0;
      for (i = 0; i < order.length && !dec.isComplete(); i++) {
        dec.receivePart(fountainPartFor('bytes', messageCbor, fragments, order[i]));
        fed++;
      }
      var seqNum = 16;
      while (!dec.isComplete() && !dec.isFailure() && seqNum <= 200) {
        dec.receivePart(fountainPartFor('bytes', messageCbor, fragments, seqNum));
        seqNum++; fed++;
      }
      if (dec.isFailure()) throw new Error('decoder failed: ' + dec.resultError);
      if (!dec.isComplete()) throw new Error('did not complete after ' + fed + ' parts');
      assertEq(bytesToHex(dec.resultMessage()), bytesToHex(messageCbor));
    });

    check('fountain decode: only mixed parts (seqNum 10..)', function () {
      var messageCbor = makeMsg256Cbor();
      var fragments = makeMsg256Fragments(messageCbor);
      var dec = new URDecoder();
      var seqNum = 10, fed = 0;
      while (!dec.isComplete() && !dec.isFailure() && seqNum <= 400) {
        dec.receivePart(fountainPartFor('bytes', messageCbor, fragments, seqNum));
        seqNum++; fed++;
      }
      if (dec.isFailure()) throw new Error('decoder failed: ' + dec.resultError);
      if (!dec.isComplete()) throw new Error('did not complete after ' + fed + ' mixed parts');
      assertEq(bytesToHex(dec.resultMessage()), bytesToHex(messageCbor));
    });

    check('fountain decode: duplicates and reversed pure parts', function () {
      var messageCbor = makeMsg256Cbor();
      var dec = new URDecoder();
      for (var i = 8; i >= 0; i--) {
        dec.receivePart(MULTIPART_REF[i]);
        dec.receivePart(MULTIPART_REF[i]); // duplicate must be harmless
      }
      if (!dec.isComplete()) throw new Error('not complete');
      assertEq(bytesToHex(dec.resultMessage()), bytesToHex(messageCbor));
    });

    check('single-part UR decodes via URDecoder', function () {
      var msg50 = new Xoshiro256('Wolf').nextData(50);
      var dec = new URDecoder();
      if (!dec.receivePart(SINGLE_PART_50.toUpperCase())) throw new Error('rejected');
      if (!dec.isComplete()) throw new Error('not complete');
      assertEq(dec.resultType, 'bytes');
      assertEq(bytesToHex(dec.resultMessage()), bytesToHex(cborBytes(msg50)));
      assertEq(dec.expectedPartCount, 1);
    });

    check('type mismatch parts are rejected', function () {
      var dec = new URDecoder();
      dec.receivePart(MULTIPART_REF[0]);
      var bad = MULTIPART_REF[1].replace('ur:bytes/', 'ur:other/');
      if (dec.receivePart(bad)) throw new Error('accepted wrong type');
      if (!dec.receivePart(MULTIPART_REF[1])) throw new Error('good part rejected after bad');
    });

    // --- ERC-4527 test vectors ---
    (vectors || []).forEach(function (vec) {
      check('vector "' + vec.name + '": urEncode matches parts', function () {
        var cbor = hexToBytes(vec.cborHex);
        var parts = urEncode(vec.urType, cbor, vec.maxFragmentLen);
        assertEq(parts, vec.parts.map(function (p) { return p.toUpperCase(); }));
      });
      check('vector "' + vec.name + '": decodes back to cborHex', function () {
        var dec = new URDecoder();
        vec.parts.forEach(function (p) {
          if (!dec.receivePart(p)) throw new Error('part rejected: ' + p.slice(0, 40));
        });
        if (!dec.isComplete()) throw new Error('not complete');
        assertEq(dec.resultType, vec.urType.toLowerCase());
        assertEq(bytesToHex(dec.resultMessage()), vec.cborHex.toLowerCase());
      });
      if (vec.parts.length > 1) {
        check('vector "' + vec.name + '": decodes in reverse order', function () {
          var dec = new URDecoder();
          vec.parts.slice().reverse().forEach(function (p) {
            if (!dec.receivePart(p.toLowerCase())) throw new Error('part rejected');
          });
          if (!dec.isComplete()) throw new Error('not complete');
          assertEq(bytesToHex(dec.resultMessage()), vec.cborHex.toLowerCase());
        });
      }
    });

    return { passed: passed, failed: failed };
  }

  // ---------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------

  return {
    sha256: sha256,
    crc32: crc32,
    bytewordsEncodeMinimal: bytewordsEncodeMinimal,
    bytewordsDecodeMinimal: bytewordsDecodeMinimal,
    Xoshiro256: Xoshiro256,
    RandomSampler: RandomSampler,
    shuffled: shuffled,
    chooseDegree: chooseDegree,
    chooseFragments: chooseFragments,
    cborUint: cborUint,
    cborBytes: cborBytes,
    decodeFountainPartCbor: decodeFountainPartCbor,
    findNominalFragmentLength: findNominalFragmentLength,
    partitionMessage: partitionMessage,
    fountainPartCbor: fountainPartCbor,
    fountainPartFor: fountainPartFor,
    urEncode: urEncode,
    isURType: isURType,
    FountainDecoder: FountainDecoder,
    URDecoder: URDecoder,
    hexToBytes: hexToBytes,
    bytesToHex: bytesToHex,
    selfTest: selfTest
  };
})();

// Node export + self-test runner
if (typeof module !== 'undefined' && module.exports) {
  module.exports = URLib;
  if (typeof require !== 'undefined' && require.main === module) {
    var fs = require('fs');
    var path = require('path');
    var vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'test-vectors.json'), 'utf8'));
    var results = URLib.selfTest(vectors, function (name, ok, detail) {
      console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  -- ' + detail : ''));
    });
    console.log('----');
    if (results.failed === 0) {
      console.log('ur.js self-test: all ' + results.passed + ' checks PASS');
    } else {
      console.log('ur.js self-test: ' + results.failed + ' FAILED, ' + results.passed + ' passed');
      process.exit(1);
    }
  }
}
