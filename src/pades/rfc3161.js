'use strict';
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const { DER } = require('./asn1_der');
const { OIDS } = require('./oids');
const { readTLV, oidFromBytes } = require('./x509_extract');

function _normalizePositiveInt(buf) {
  if (!buf || !buf.length) return Buffer.from([0x00]);
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0x00) i++;
  return Buffer.from(buf.slice(i));
}

/**
 * RFC 3161 TimeStampReq oluşturur (DOĞRU ASN.1):
 * TimeStampReq ::= SEQUENCE {
 *   version           INTEGER (1),
 *   messageImprint    SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING },
 *   reqPolicy         OBJECT IDENTIFIER OPTIONAL,
 *   nonce             INTEGER OPTIONAL,
 *   certReq           BOOLEAN DEFAULT FALSE,
 *   extensions        [0] EXPLICIT Extensions OPTIONAL
 * }
 */
function buildTSQ(
  messageDigest,
  {
    hashOid = OIDS.sha256,
    certReq = true,
    reqPolicyOid = null,
    nonceBytes = 16,       // 0 => nonce gönderme
  } = {},
) {
  const version = Buffer.from([0x02, 0x01, 0x01]); // INTEGER 1
  const imprint = DER.seq(DER.algo(hashOid), DER.octet(messageDigest));

  const parts = [version, imprint];
  let nonceValue = null;

  if (reqPolicyOid) {
    // DİKKAT: reqPolicy DÜZ OID (context-tag YOK)
    parts.push(DER.oid(reqPolicyOid));
  }

  if (nonceBytes && nonceBytes > 0) {
    // DÜZ INTEGER (context-tag YOK). Pozitif için gerekirse 0x00 ön eklenir.
    const nonce = crypto.randomBytes(nonceBytes);
    nonceValue = _normalizePositiveInt(nonce);
    parts.push(DER.intFromBuf(nonce));
  }

  // DÜZ BOOLEAN (context-tag YOK). DEFAULT FALSE; TRUE gönderiyoruz.
  if (typeof certReq === 'boolean') {
    parts.push(Buffer.from([0x01, 0x01, certReq ? 0xff : 0x00]));
  }

  // extensions [0] EXPLICIT OPTIONAL — kullanmıyoruz
  return { der: DER.seq(...parts), nonce: nonceValue };
}

/** Yanıtı POST eder (DER ya da base64 olabilir), normalize eder */
function requestTimestamp(tsaUrl, tsqDer, extraHeaders = {}) {
  const u = new URL(tsaUrl);
  const isHttps = u.protocol === 'https:';
  const opts = {
    hostname: u.hostname,
    port: u.port || (isHttps ? 443 : 80),
    path: u.pathname + (u.search || ''),
    method: 'POST',
    headers: {
      'Content-Type': 'application/timestamp-query',
      'Accept': 'application/timestamp-reply,application/pkcs7-mime,application/octet-stream,*/*',
      'Content-Length': Buffer.byteLength(tsqDer),
      'User-Agent': 'Node-PAdES/1.0',
      ...extraHeaders
    }
  };
  const agent = isHttps ? https : http;

  return new Promise((resolve, reject) => {
    const req = agent.request(opts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`TSA HTTP ${res.statusCode}`));
        }
        const der = _maybeBase64ToDer(body);
        resolve({ der, contentType: res.headers['content-type'] });
      });
    });
    req.on('error', reject);
    req.write(tsqDer);
    req.end();
  });
}

function _maybeBase64ToDer(buf) {
  const s = buf.toString('ascii');
  if (/^-----BEGIN[\s\S]+-----/i.test(s)) {
    const b64 = s.replace(/-----BEGIN[\s\S]+?-----/g, '')
                 .replace(/-----END[\s\S]+?-----/g, '')
                 .replace(/\s+/g, '');
    return Buffer.from(b64, 'base64');
  }
  if (/^[A-Za-z0-9+/=\r\n]+$/.test(s) && s.replace(/\s+/g, '').length % 4 === 0) {
    try { return Buffer.from(s.replace(/\s+/g, ''), 'base64'); } catch {}
  }
  return buf;
}

function _isContentInfoSignedData(der) {
  try {
    const outer = readTLV(der, 0);
    if (outer.tag !== 0x30) return false;
    const ct = readTLV(der, outer.start);
    if (ct.tag !== 0x06) return false;
    return oidFromBytes(der.slice(ct.start, ct.end)) === OIDS.signedData;
  } catch {
    return false;
  }
}

function extractTimeStampTokenOrThrow(tsRespDer, opts = {}) {
  let tokenDer;
  if (_isContentInfoSignedData(tsRespDer)) {
    tokenDer = Buffer.from(tsRespDer);
  } else {
    const outer = readTLV(tsRespDer, 0);
    if (outer.tag !== 0x30) throw new Error('Bad TSA response (not SEQUENCE)');

    const status = readTLV(tsRespDer, outer.start); // PKIStatusInfo
    if (status.tag !== 0x30) throw new Error('Bad TSA response (status missing)');

    const stInt = readTLV(tsRespDer, status.start);
    if (stInt.tag !== 0x02) throw new Error('Bad TSA response (no status INTEGER)');
    const statusVal = parseInt(tsRespDer.slice(stInt.start, stInt.end).toString('hex') || '00', 16);

    if (statusVal === 0 || statusVal === 1) {
      if (status.next >= outer.next) throw new Error('TSA granted but no timeStampToken present');
      const tok = readTLV(tsRespDer, status.next);
      if (tok.tag !== 0x30) throw new Error('Bad timeStampToken');
      tokenDer = Buffer.from(tsRespDer.slice(status.next, tok.next));
    } else {
      let p = stInt.next, statusString = null, failInfoBits = null;
      while (p < status.next) {
        const el = readTLV(tsRespDer, p);
        if ((el.tag & 0xE0) === 0xA0) { // [0] EXPLICIT: PKIFreeText
          try {
            const seq = readTLV(tsRespDer, el.start);
            let q = seq.start; const parts = [];
            while (q < seq.next) {
              const s = readTLV(tsRespDer, q);
              parts.push(tsRespDer.slice(s.start, s.end).toString('latin1'));
              q = s.next;
            }
            statusString = parts.join(' | ');
          } catch {}
        } else if ((el.tag & 0xE0) === 0xA0 + 1) { // [1] failInfo BIT STRING
          const bitStr = tsRespDer.slice(el.start, el.end);
          const bs = readTLV(bitStr, 0);
          if (bs.tag === 0x03) failInfoBits = bitStr.slice(bs.start, bs.end);
        }
        p = el.next;
      }

      const codeMap = { 2: 'rejection', 3: 'waiting', 4: 'revocationWarning', 5: 'revocationNotification' };
      const code = codeMap[statusVal] || `unknown(${statusVal})`;
      let failBits = '';
      if (failInfoBits) {
        const b = failInfoBits[failInfoBits.length - 1] || 0;
        const flags = [];
        if (b & 0x80) flags.push('badAlg');
        if (b & 0x40) flags.push('badRequest');
        if (b & 0x20) flags.push('badDataFormat');
        if (b & 0x10) flags.push('timeNotAvailable');
        if (b & 0x08) flags.push('unacceptedPolicy');
        if (b & 0x04) flags.push('unacceptedExtension');
        if (b & 0x02) flags.push('addInfoNotAvailable');
        if (b & 0x01) flags.push('systemFailure');
        failBits = flags.join(',');
      }
      const msg = `TSA status=${code}` + (statusString ? `, statusString="${statusString}"` : '') + (failBits ? `, failInfo=[${failBits}]` : '');
      throw new Error(msg);
    }
  }

  let info = null;
  if (opts && (opts.expectedImprint || opts.expectedNonce || opts.expectedHashOid)) {
    info = _parseTimeStampTokenInfo(tokenDer);
    _validateTSTInfo(info, opts);
  }

  return tokenDer;
}

function _parseTimeStampTokenInfo(tsTokenDer) {
  const outer = readTLV(tsTokenDer, 0);
  if (outer.tag !== 0x30) throw new Error('timeStampToken not SEQUENCE');

  const ct = readTLV(tsTokenDer, outer.start);
  if (ct.tag !== 0x06) throw new Error('timeStampToken missing contentType');
  if (oidFromBytes(tsTokenDer.slice(ct.start, ct.end)) !== OIDS.signedData) {
    throw new Error('timeStampToken contentType is not signedData');
  }

  const content = readTLV(tsTokenDer, ct.next);
  if ((content.tag & 0xE0) !== 0xA0) throw new Error('timeStampToken missing SignedData');
  const signedData = readTLV(tsTokenDer, content.start);
  if (signedData.tag !== 0x30) throw new Error('timeStampToken SignedData malformed');

  let p = signedData.start;
  const version = readTLV(tsTokenDer, p);
  if (version.tag !== 0x02) throw new Error('SignedData.version missing');
  p = version.next;

  const digestAlgs = readTLV(tsTokenDer, p);
  if (digestAlgs.tag !== 0x31) throw new Error('SignedData.digestAlgorithms missing');
  p = digestAlgs.next;

  const eci = readTLV(tsTokenDer, p);
  if (eci.tag !== 0x30) throw new Error('SignedData.encapContentInfo malformed');
  const eciType = readTLV(tsTokenDer, eci.start);
  if (eciType.tag !== 0x06) throw new Error('SignedData.encapContentInfo missing type');
  const eciTypeOid = oidFromBytes(tsTokenDer.slice(eciType.start, eciType.end));
  const isDataContent = eciTypeOid === OIDS.data;
  const isTstInfoContent = OIDS.tstInfo && eciTypeOid === OIDS.tstInfo;
  if (!isDataContent && !isTstInfoContent) {
    throw new Error(`timeStampToken eContentType not supported: ${eciTypeOid}`);
  }

  let tstInfoDer = null;
  if (eciType.next < eci.end) {
    const eciContent = readTLV(tsTokenDer, eciType.next);
    if ((eciContent.tag & 0xE0) === 0xA0) {
      const oct = readTLV(tsTokenDer, eciContent.start);
      if (oct.tag === 0x04) {
        tstInfoDer = Buffer.from(tsTokenDer.slice(oct.start, oct.end));
      }
    }
  }
  if (!tstInfoDer) throw new Error('timeStampToken missing TSTInfo');

  const tstSeq = readTLV(tstInfoDer, 0);
  if (tstSeq.tag !== 0x30) throw new Error('TSTInfo not SEQUENCE');
  let q = tstSeq.start;

  const tstVersion = readTLV(tstInfoDer, q);
  if (tstVersion.tag !== 0x02) throw new Error('TSTInfo.version missing');
  q = tstVersion.next;

  const policy = readTLV(tstInfoDer, q);
  if (policy.tag !== 0x06) throw new Error('TSTInfo.policy missing');
  q = policy.next;

  const mi = readTLV(tstInfoDer, q);
  if (mi.tag !== 0x30) throw new Error('TSTInfo.messageImprint malformed');
  const miAlg = readTLV(tstInfoDer, mi.start);
  if (miAlg.tag !== 0x30) throw new Error('TSTInfo.messageImprint.hashAlgorithm malformed');
  const miAlgOid = readTLV(tstInfoDer, miAlg.start);
  if (miAlgOid.tag !== 0x06) throw new Error('TSTInfo.messageImprint.hashAlgorithm missing OID');
  const hashAlgOidBuf = Buffer.from(tstInfoDer.slice(miAlgOid.start, miAlgOid.end));
  const hashedMsg = readTLV(tstInfoDer, miAlg.next);
  if (hashedMsg.tag !== 0x04) throw new Error('TSTInfo.hashedMessage missing');
  const hashedMessage = Buffer.from(tstInfoDer.slice(hashedMsg.start, hashedMsg.end));
  q = mi.next;

  const serial = readTLV(tstInfoDer, q);
  if (serial.tag !== 0x02) throw new Error('TSTInfo.serialNumber missing');
  q = serial.next;

  const genTime = readTLV(tstInfoDer, q);
  if (!(genTime.tag === 0x18 || genTime.tag === 0x17)) throw new Error('TSTInfo.genTime missing');
  q = genTime.next;

  let nonce = null;
  while (q < tstSeq.next) {
    const tlv = readTLV(tstInfoDer, q);
    if ((tlv.tag & 0xE0) === 0xA0) {
      const tagNo = tlv.tag & 0x1F;
      if (tagNo === 1) {
        const inner = readTLV(tstInfoDer, tlv.start);
        if (inner.tag === 0x02) {
          nonce = Buffer.from(tstInfoDer.slice(inner.start, inner.end));
        }
      }
    }
    q = tlv.next;
  }

  return { hashAlgorithmOid: hashAlgOidBuf, hashedMessage, nonce };
}

function _oidValueBytes(oidStr) {
  const der = DER.oid(oidStr);
  const tlv = readTLV(der, 0);
  return Buffer.from(der.slice(tlv.start, tlv.end));
}

function _validateTSTInfo(info, opts) {
  if (!opts) return;
  if (opts.expectedHashOid) {
    const wantOid = Buffer.isBuffer(opts.expectedHashOid)
      ? Buffer.from(opts.expectedHashOid)
      : _oidValueBytes(opts.expectedHashOid);
    if (!Buffer.from(info.hashAlgorithmOid).equals(wantOid)) {
      throw new Error('TSA token hashAlgorithm mismatch');
    }
  }
  if (opts.expectedImprint) {
    const want = Buffer.from(opts.expectedImprint);
    if (info.hashedMessage.length !== want.length || !info.hashedMessage.equals(want)) {
      throw new Error('TSA token hashedMessage mismatch');
    }
  }
  if (opts.expectedNonce) {
    const want = _normalizePositiveInt(Buffer.from(opts.expectedNonce));
    const allowMissingNonce = opts.allowMissingNonce !== undefined ? opts.allowMissingNonce : true;
    if (!info.nonce) {
      if (!allowMissingNonce) {
        throw new Error('TSA token missing nonce');
      }
    } else {
      const got = _normalizePositiveInt(info.nonce);
      if (!got.equals(want)) {
        throw new Error('TSA token nonce mismatch');
      }
    }
  } else if (opts.allowMissingNonce === false && !info.nonce) {
    // Preserve strict behaviour when explicitly requested even without an expected nonce
    throw new Error('TSA token missing nonce');
  }
}

module.exports = { buildTSQ, requestTimestamp, extractTimeStampTokenOrThrow, _validateTSTInfo };
