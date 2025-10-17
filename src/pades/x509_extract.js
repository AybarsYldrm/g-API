'use strict';
const { recommendHashForCurve } = require('./oids');

function pemToDer(pem){
  const b64 = String(pem).replace(/-----(BEGIN|END) CERTIFICATE-----/g,'').replace(/\s+/g,'');
  return Buffer.from(b64, 'base64');
}
function readTLV(buf, pos){
  const t = buf[pos]; let l = buf[pos+1], lenBytes = 1;
  if (l & 0x80) { const n=l&0x7F; l=0; for(let i=0;i<n;i++) l=(l<<8)|buf[pos+2+i]; lenBytes=1+n; }
  const hdr = 1 + lenBytes, start = pos + hdr, end = start + l;
  return { tag:t, len:l, hdr, start, end, next:end };
}
function oidFromBytes(bytes){
  const b=Buffer.from(bytes); if(!b.length) throw new Error('empty OID');
  const first=b[0]; const arcs=[Math.floor(first/40), first%40]; let val=0;
  for(let i=1;i<b.length;i++){ const v=b[i]; val=(val<<7)|(v&0x7f); if(!(v&0x80)){ arcs.push(val); val=0; } }
  return arcs.join('.');
}

/** issuer (DER incl tag+len), serial content, SPKI alg OID, curve OID, recommended hash */
function parseCertBasics(certDer){
  let tlv = readTLV(certDer, 0); if (tlv.tag!==0x30) throw new Error('bad cert outer');
  let p = tlv.start;
  const tbs = readTLV(certDer, p); if (tbs.tag!==0x30) throw new Error('bad tbs'); p=tbs.start;
  let v = readTLV(certDer, p); if (v.tag===0xA0) p=v.next; // version
  const serial = readTLV(certDer, p); if (serial.tag!==0x02) throw new Error('no serial'); const serialContent = certDer.slice(serial.start, serial.end); p=serial.next;
  v = readTLV(certDer, p); if (v.tag!==0x30) throw new Error('no sigalg'); p=v.next;
  const issuer = readTLV(certDer, p); if (issuer.tag!==0x30) throw new Error('no issuer');
  const issuerFullDER = certDer.slice(issuer.start - issuer.hdr, issuer.end); p=issuer.next;
  v = readTLV(certDer, p); if (v.tag!==0x30) throw new Error('no validity'); p=v.next;
  v = readTLV(certDer, p); if (v.tag!==0x30) throw new Error('no subject'); p=v.next;

  const spki = readTLV(certDer, p); if (spki.tag!==0x30) throw new Error('no spki');
  const spkiAlg = readTLV(certDer, spki.start); if (spkiAlg.tag!==0x30) throw new Error('spki.alg');
  const algOidTLV = readTLV(certDer, spkiAlg.start); if (algOidTLV.tag!==0x06) throw new Error('spki.alg.oid');
  const spkiAlgOid = oidFromBytes(certDer.slice(algOidTLV.start, algOidTLV.end));
  let ecCurveOid = null;
  if (spkiAlgOid === '1.2.840.10045.2.1') { // idEcPublicKey
    const params = readTLV(certDer, algOidTLV.next);
    if (params.tag === 0x06) ecCurveOid = oidFromBytes(certDer.slice(params.start, params.end));
  }
  let recommendedHash = 'sha256';
  if (spkiAlgOid === '1.2.840.10045.2.1' && ecCurveOid) recommendedHash = recommendHashForCurve(ecCurveOid);
  return { issuerFullDER, serialContent, spkiAlgOid, ecCurveOid, recommendedHash };
}

/** Minimal KeyUsage & EKU parse (digitalSignature / contentCommitment / keyAgreement) */
function parseKeyUsageAndEKU(certDer){
  function tlv(buf,pos){ const t=buf[pos]; let l=buf[pos+1], n=1; if(l&0x80){const k=l&0x7F; l=0; for(let i=0;i<k;i++) l=(l<<8)|buf[pos+2+i]; n=1+k;} const s=pos+1+n, e=s+l; return {t,l,h:1+n,s,e,nxt:e}; }
  function bytesToOid(bytes){ const b=Buffer.from(bytes); const f=b[0]; const arcs=[Math.floor(f/40), f%40]; let v=0; for(let i=1;i<b.length;i++){ const c=b[i]; v=(v<<7)|(c&0x7f); if(!(c&0x80)){ arcs.push(v); v=0; } } return arcs.join('.'); }
  const out = { keyUsage:{}, eku:[] };

  let p = tlv(certDer,0).s; const tbs = tlv(certDer,p); p = tbs.s;
  let v = tlv(certDer,p); if (v.t===0xA0) p=v.nxt; // version
  p = tlv(certDer,p).nxt; // serial
  p = tlv(certDer,p).nxt; // sigalg
  p = tlv(certDer,p).nxt; // issuer
  p = tlv(certDer,p).nxt; // validity
  p = tlv(certDer,p).nxt; // subject
  p = tlv(certDer,p).nxt; // spki

  // optional [1],[2]
  for (let i=0;i<2;i++){ const maybe = tlv(certDer,p); if (maybe.t === (0xA1+i)) p = maybe.nxt; }

  const ext = tlv(certDer,p);
  if (ext.t!==0xA3) return out; // no extensions

  const seq = tlv(certDer, ext.s);
  let q = seq.s;
  while (q < seq.nxt){
    const e = tlv(certDer, q); q = e.nxt; // Extension (SEQ)
    let r = e.s;
    const oidT = tlv(certDer,r); const oid = bytesToOid(certDer.slice(oidT.s, oidT.e)); r = oidT.nxt;
    const maybeBool = tlv(certDer,r); if (maybeBool.t===0x01) r = maybeBool.nxt; // critical ignored
    const valOct = tlv(certDer,r); const val = certDer.slice(valOct.s, valOct.e);

    if (oid === '2.5.29.15'){ // KeyUsage
      const bs = tlv(val,0); if (bs.t!==0x03) continue;
      const bitstr = val.slice(bs.s+1, bs.e); const b0 = bitstr[0]||0;
      out.keyUsage.digitalSignature  = !!(b0 & 0x80);
      out.keyUsage.contentCommitment = !!(b0 & 0x40);
      out.keyUsage.keyAgreement      = !!(b0 & 0x08);
    } else if (oid === '2.5.29.37'){ // EKU
      const s2 = tlv(val,0); if (s2.t!==0x30) continue;
      let z = s2.s; while (z < s2.nxt){ const o = tlv(val,z); if (o.t===0x06) out.eku.push(bytesToOid(val.slice(o.s,o.e))); z = o.nxt; }
    }
  }
  return out;
}

module.exports = { pemToDer, parseCertBasics, parseKeyUsageAndEKU, readTLV, oidFromBytes };
