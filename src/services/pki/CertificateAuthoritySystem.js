'use strict';

// authority_system.js
// Mini PKI/CA (OpenSSL yok) — yalnızca EC P-256 (ECDSA/ECDH)
// Root → kullanıcı: key, CSR, cert. Dış CSR imzalama. SKI/AKI/KU/EKU/SAN.
// RFC uyumlu: SKI=OCTET içinde OCTET(DER), Extensions [3] EXPLICIT, SAN dedup.
// EC özel anahtar: PKCS#8 veya SEC1. Üretim sonrası parse+verify garanti.
// Issuer DER meta.json -> subjectJson'dan yeniden inşa edilir (slice sapmaları yok).

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { X509Certificate } = crypto;

const DEFAULT_CONFIG = {
  subjectJson: null,
  keyType: 'EC',
  curve: 'prime256v1',
  ecPrivateKeyFormat: 'pkcs8',
  createdAt: null,
  services: {
    ocspUrl: null,
    crlUrl: null,
    caIssuersUrl: 'https://fitfak.net/aia/ca.crt'
  },
  ocspNextUpdateSeconds: 12 * 3600,
  crlNextUpdateSeconds: 7 * 24 * 3600,
  autoRenewThresholdDays: 15
};

/* ================= Utils ================= */
const ensureDir = d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); };
function atomicWrite(p, data) { ensureDir(path.dirname(p)); const tmp = path.join(path.dirname(p), `.tmp-${process.pid}-${Date.now()}`); fs.writeFileSync(tmp, data); fs.renameSync(tmp, p); }
const readIf = (p, d=null) => { try { return fs.readFileSync(p, 'utf8'); } catch { return d; } };
const toPEM = (der, label) => `-----BEGIN ${label}-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
function fromPEM(pem, label) { const m=new RegExp(`-----BEGIN ${label}-----([^-]+)-----END ${label}-----`, 's').exec(pem||''); if(!m) throw new Error(`Invalid ${label} PEM`); return Buffer.from(m[1].replace(/\s+/g,''),'base64'); }
const sha1 = b => crypto.createHash('sha1').update(b).digest();
const randPos = n => { const b = crypto.randomBytes(n); b[0] &= 0x7f; return b; };
const moveIfExists = (src, dst) => {
  if(!src || !dst || src === dst) return;
  try {
    if(fs.existsSync(src) && !fs.existsSync(dst)){
      ensureDir(path.dirname(dst));
      fs.renameSync(src, dst);
    }
  } catch {}
};
const bufToBigInt = buf => buf.reduce((acc, cur) => (acc << 8n) | BigInt(cur), 0n);
const bigIntToBuf = num => {
  if (num === 0n) return Buffer.from([0]);
  const out = [];
  let n = num;
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  return Buffer.from(out);
};
const bufToHex = buf => {
  let hex = buf.toString('hex');
  hex = hex.replace(/^0+(?=[0-9a-f])/i, '');
  return hex.length ? hex : '00';
};
const pruneObject = obj => {
  if(!obj || typeof obj !== 'object') return obj;
  const out = {};
  for(const [key, value] of Object.entries(obj)){
    if(value === null || value === undefined) continue;
    if(Array.isArray(value)){
      const filtered = value.map(item => item).filter(item => item !== null && item !== undefined && item !== '');
      if(filtered.length) out[key] = filtered;
      continue;
    }
    out[key] = value;
  }
  return out;
};
const sanitizeHexString = value => {
  if(value === null || value === undefined) return null;
  let hex = String(value).trim().toLowerCase().replace(/[^0-9a-f]/g, '');
  if(!hex) return null;
  hex = hex.replace(/^0+(?=[0-9a-f])/,'' );
  return hex || '0';
};
const generalNameURI = uri => {
  const data = Buffer.from(uri, 'ascii');
  return Buffer.concat([Buffer.from([0x86]), derLen(data.length), data]);
};
const implicitTag = (tag, der) => {
  if(!der || der.length < 2) return Buffer.from([tag, 0x00]);
  const { hdr } = readLen(der, 1);
  return Buffer.concat([Buffer.from([tag]), der.slice(1, 1 + hdr), der.slice(1 + hdr)]);
};
const isHostname = s => /^[a-z0-9.-]+$/i.test(s||'');
const isCertPEM = p => /-----BEGIN CERTIFICATE-----/.test(p) && !/BEGIN CERTIFICATE REQUEST/.test(p);

/* ============== DER/ASN.1 ============== */
const T={ SEQ:0x30, SET:0x31, INT:0x02, BIT:0x03, OCT:0x04, NULL:0x05, OID:0x06, UTF8:0x0c, PRINT:0x13, IA5:0x16, UTCT:0x17, GENT:0x18, CTX0:0xa0, CTX3:0xa3 };
const SEQ=(...c)=>wrap(T.SEQ,Buffer.concat(c)), SET=(...c)=>wrap(T.SET,Buffer.concat(c));
const NULL=()=>wrap(T.NULL,Buffer.alloc(0)), OCT=b=>wrap(T.OCT,b), IA5=s=>wrap(T.IA5,Buffer.from(s,'ascii'));
const UTF8=s=>wrap(T.UTF8,Buffer.from(s,'utf8')), PRINT=s=>wrap(T.PRINT,Buffer.from(s,'ascii')), CTX=(tag,inner)=>wrap(tag,inner);
function derLen(n){ if(n<128) return Buffer.from([n]); const a=[]; for(let x=n;x>0;x>>=8)a.unshift(x&0xff); return Buffer.from([0x80|a.length,...a]); }
function wrap(tag,content){ return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]); }
function OID(s){ const ps=s.split('.').map(x=>BigInt(x)); const f=Number(ps[0]*40n+ps[1]); const out=[f]; for(let i=2;i<ps.length;i++){ let n=ps[i], t=[]; do{ t.unshift(Number(n&0x7fn)); n>>=7n; }while(n>0n); for(let j=0;j<t.length-1;j++) t[j]|=0x80; out.push(...t);} return wrap(T.OID,Buffer.from(out)); }
function INTpos(buf){ if(buf.length===0) buf=Buffer.from([0]); if(buf[0]&0x80) buf=Buffer.concat([Buffer.from([0x00]),buf]); return wrap(T.INT,buf); }
const INTi=n=>INTpos(Buffer.from([n]));
function BIT(bytes,unused=0){ return wrap(T.BIT,Buffer.concat([Buffer.from([unused]),bytes])); }
function readLen(buf,off){ const f=buf[off]; if((f&0x80)===0) return {len:f,hdr:1}; const n=f&0x7f; let v=0; for(let i=0;i<n;i++) v=(v<<8)|buf[off+1+i]; return {len:v,hdr:1+n}; }
function readTLV(buf,off){ const tag=buf[off]; const {len,hdr}=readLen(buf,off+1); const start=off+1+hdr, end=start+len; return {tag,len,start,end,total:end-off}; }
function derTime(d){ const y=d.getUTCFullYear(), p=(n,w=2)=>String(n).padStart(w,'0'); if(y>=1950&&y<=2049) return wrap(T.UTCT,Buffer.from(`${p(y%100)}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`,'ascii')); return wrap(T.GENT,Buffer.from(`${y}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`,'ascii')); }
function generalizedTime(input){ const d=input instanceof Date?input:new Date(input); if(Number.isNaN(d.valueOf())) throw new Error('Invalid date for GeneralizedTime'); const p=(n)=>String(n).padStart(2,'0'); const s=`${d.getUTCFullYear()}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`; return wrap(T.GENT,Buffer.from(s,'ascii')); }

/* OIDs */
const O={
  at:{ C:'2.5.4.6', ST:'2.5.4.8', L:'2.5.4.7', O:'2.5.4.10', OU:'2.5.4.11', CN:'2.5.4.3', email:'1.2.840.113549.1.9.1' },
  alg:{ ecdsa_sha256:'1.2.840.10045.4.3.2', id_ecPublicKey:'1.2.840.10045.2.1', prime256v1:'1.2.840.10045.3.1.7', sha1:'1.3.14.3.2.26' },
  ext:{
    basicConstraints:'2.5.29.19',
    keyUsage:'2.5.29.15',
    extKeyUsage:'2.5.29.37',
    subjectAltName:'2.5.29.17',
    subjectKeyIdentifier:'2.5.29.14',
    authorityKeyIdentifier:'2.5.29.35',
    cRLDistributionPoints:'2.5.29.31',
    authorityInfoAccess:'1.3.6.1.5.5.7.1.1',
    cRLNumber:'2.5.29.20',
    cRLReason:'2.5.29.21'
  },
  ocsp:{ basic:'1.3.6.1.5.5.7.48.1', basicResponse:'1.3.6.1.5.5.7.48.1.1', nonce:'1.3.6.1.5.5.7.48.1.2', caIssuers:'1.3.6.1.5.5.7.48.2' },
  eku:{
    serverAuth:'1.3.6.1.5.5.7.3.1',
    clientAuth:'1.3.6.1.5.5.7.3.2',
    codeSigning:'1.3.6.1.5.5.7.3.3',
    emailProtection:'1.3.6.1.5.5.7.3.4'
  },
  pkcs9:{ extensionRequest:'1.2.840.113549.1.9.14' }
};

const CRL_REASON_MAP = {
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  aACompromise: 10
};

const OCSP_RESPONSE_STATUS = {
  successful: 0,
  malformedRequest: 1,
  internalError: 2,
  tryLater: 3,
  sigRequired: 5,
  unauthorized: 6
};

/* DN / Subject */
function rdn(oid,val,enc='utf8'){ const v=enc==='print'?PRINT(val):enc==='ia5'?IA5(val):UTF8(val); return SET(SEQ(OID(oid),v)); }
function subjectFromJSON(j){ const order=['C','ST','L','O','OU','CN','emailAddress']; const map={ C:O.at.C, ST:O.at.ST, L:O.at.L, O:O.at.O, OU:O.at.OU, CN:O.at.CN, emailAddress:O.at.email }; const enc=k=>k==='C'?'print':(k==='emailAddress'?'ia5':'utf8'); return SEQ(...order.filter(k=>j[k]).map(k=>rdn(map[k],String(j[k]),enc(k)))); }

/* SAN */
function encSAN(list=[]){ if(!list.length) return null; const it=[]; for(const s of list){ const [t,v]=s.split(':'); if(t==='DNS'){ const b=Buffer.from(v,'ascii'); it.push(Buffer.concat([Buffer.from([0x82]), derLen(b.length), b])); } else if(t==='IP'){ const b=Buffer.from(v.split('.').map(x=>parseInt(x,10))); it.push(Buffer.concat([Buffer.from([0x87]), derLen(b.length), b])); } else if(t==='email'){ const b=Buffer.from(v,'ascii'); it.push(Buffer.concat([Buffer.from([0x81]), derLen(b.length), b])); } } return SEQ(...it); }

/* Extensions (RFC-true) */
function extBasicConstraints({ca=false,pathLen=null,critical=true}={}){ const parts=[]; if(ca) parts.push(Buffer.from([0x01,0x01,0xff])); if(pathLen!=null) parts.push(INTpos(Buffer.from([pathLen]))); const crit=critical?Buffer.from([0x01,0x01,0xff]):Buffer.alloc(0); return SEQ(OID(O.ext.basicConstraints), crit, OCT(SEQ(...parts))); }
function extKeyUsage({ digitalSignature=false, contentCommitment=false, keyEncipherment=false, dataEncipherment=false, keyAgreement=false, keyCertSign=false, cRLSign=false, encipherOnly=false, decipherOnly=false, critical=true }={}){
  const bits=[];
  const ensureByte = idx => {
    const byteIndex = Math.floor(idx/8);
    while(bits.length <= byteIndex) bits.push(0x00);
    return byteIndex;
  };
  const set = idx => {
    const byteIndex = ensureByte(idx);
    const bitPos = 7 - (idx % 8);
    bits[byteIndex] |= (1 << bitPos);
  };
  if(digitalSignature) set(0);
  if(contentCommitment) set(1);
  if(keyEncipherment) set(2);
  if(dataEncipherment) set(3);
  if(keyAgreement) set(4);
  if(keyCertSign) set(5);
  if(cRLSign) set(6);
  if(encipherOnly) set(7);
  if(decipherOnly) set(8);
  if(!bits.length) return null;
  const crit = critical ? Buffer.from([0x01,0x01,0xff]) : Buffer.alloc(0);
  const bitString = BIT(Buffer.from(bits),0);
  return SEQ(OID(O.ext.keyUsage), crit, OCT(bitString));
}
function extEKU(options={}){
  let critical=false;
  let usages=[];
  if(Array.isArray(options)){
    usages = options.slice();
  } else {
    const { critical:crit=false, usages:explicitList=null, ...flags } = options;
    critical = !!crit;
    if(Array.isArray(explicitList)){
      usages = explicitList.slice();
    } else {
      usages = Object.entries(flags).filter(([,enabled]) => !!enabled).map(([name]) => name);
    }
  }
  const oids = usages
    .map(name => O.eku[name])
    .filter(Boolean)
    .map(oid => OID(oid));
  if(!oids.length) return null;
  const crit = critical ? Buffer.from([0x01,0x01,0xff]) : Buffer.alloc(0);
  return SEQ(OID(O.ext.extKeyUsage), crit, OCT(SEQ(...oids)));
}
function extSAN(list){ if(!list||!list.length) return null; return SEQ(OID(O.ext.subjectAltName), Buffer.alloc(0), OCT(encSAN(list))); }

function crlReasonExtension(code){
  if(code == null) return null;
  const body = wrap(0x0a, Buffer.from([code]));
  return SEQ(OID(O.ext.cRLReason), OCT(body));
}

function extCRLDistributionPoints(urls=[]){
  if(!urls || !urls.length) return null;
  const points = urls
    .filter(Boolean)
    .map(url => {
      const generalNames = SEQ(generalNameURI(url));
      const fullName = implicitTag(0xa0, generalNames); // DistributionPointName -> fullName [0] (IMPLICIT)
      const distributionPoint = wrap(0xa0, fullName); // distributionPoint [0]
      return SEQ(distributionPoint);
    });
  if(!points.length) return null;
  return SEQ(OID(O.ext.cRLDistributionPoints), Buffer.alloc(0), OCT(SEQ(...points)));
}

function extAuthorityInfoAccess({ ocspUrl=null, caIssuersUrl=null }={}){
  const entries = [];
  if(ocspUrl){
    entries.push(SEQ(OID(O.ocsp.basic), generalNameURI(ocspUrl)));
  }
  if(caIssuersUrl){
    entries.push(SEQ(OID(O.ocsp.caIssuers), generalNameURI(caIssuersUrl)));
  }
  if(!entries.length) return null;
  return SEQ(OID(O.ext.authorityInfoAccess), Buffer.alloc(0), OCT(SEQ(...entries)));
}


// SKI (extnValue OCTET( OCTET(DER(keyId)) ))
const extSKI = keyId =>
  SEQ(OID(O.ext.subjectKeyIdentifier), Buffer.alloc(0), OCT( wrap(0x04, keyId) ));

// AKI (keyIdentifier)
const extAKI = keyId => SEQ(OID(O.ext.authorityKeyIdentifier), Buffer.alloc(0),
  OCT( SEQ(Buffer.concat([Buffer.from([0x80]), derLen(keyId.length), keyId])) )
);

const wrapExts = exts => SEQ(...exts.filter(Boolean));

/* Robust SPKI bits */
function spkiSubjectBits(spkiDer){
  const top = readTLV(spkiDer,0);
  if (top.tag !== T.SEQ) throw new Error('SPKI top not SEQ');
  let p=top.start, bit=null;
  while(p<top.end){ const tlv=readTLV(spkiDer,p); if(tlv.tag===T.BIT){ bit=tlv; break; } p=tlv.end; }
  if(!bit) throw new Error('SPKI subjectPublicKey BIT not found');
  return spkiDer.slice(bit.start+1, bit.end);
}

/* Issuer name DER'i almak için TBS parse */
function parseCertTbs(certDer){ const top=readTLV(certDer,0); if(top.tag!==T.SEQ) throw new Error('Certificate top not SEQ'); const tbs=readTLV(certDer, top.start); if(tbs.tag!==T.SEQ) throw new Error('TBSCertificate not SEQ'); return tbs; }
function issuerNameDER(certDer, tbs){
  let p=tbs.start;
  const maybeV=readTLV(certDer,p); if(maybeV.tag===T.CTX0) p=maybeV.end; // version
  p=readTLV(certDer,p).end; // serial
  p=readTLV(certDer,p).end; // signature
  const issuer=readTLV(certDer,p); if(issuer.tag!==T.SEQ) throw new Error('Issuer not SEQ');
  return certDer.slice(issuer.start, issuer.end);
}

/* Alg IDs */
const algIdForSigner = kind => {
  if(kind !== 'EC') throw new Error(`Unsupported signer kind: ${kind}`);
  return SEQ(OID(O.alg.ecdsa_sha256));
};
const csrSigAlgForKeyObject = keyObj => {
  if(keyObj.asymmetricKeyType !== 'ec') throw new Error('CSR yalnızca EC anahtarları ile imzalanabilir');
  return SEQ(OID(O.alg.ecdsa_sha256));
};

/* Build/sign cert */
function assertIsSequence(der, what='value'){
  if (!der || der[0] !== 0x30) {
    const got = der ? '0x'+der[0].toString(16) : 'null';
    throw new Error(`ASN.1: ${what} not SEQUENCE (0x30). got=${got}, len=${der?der.length:0}`);
  }
}
function buildTBS({serialBuf, issuerDer, subjectDer, spkiDer, notBefore, notAfter, extensionsDer, signerKind}){
  assertIsSequence(issuerDer,'issuer'); assertIsSequence(subjectDer,'subject'); assertIsSequence(spkiDer,'spki');
  if (extensionsDer) assertIsSequence(extensionsDer,'extensions');
  const v3=CTX(T.CTX0, INTi(2));
  const validity=SEQ(derTime(notBefore), derTime(notAfter));
  const sigAlg=algIdForSigner(signerKind);
  const parts=[v3, INTpos(serialBuf), sigAlg, issuerDer, validity, subjectDer, spkiDer];
  if(extensionsDer&&extensionsDer.length) parts.push(CTX(T.CTX3, extensionsDer));
  return SEQ(...parts);
}
function signCert(tbsDer, signerPrivPem, signerKind){
  const alg = algIdForSigner(signerKind);
  const sig = crypto.sign('sha256', tbsDer, signerPrivPem);
  return SEQ(tbsDer, alg, BIT(sig,0));
}

/* CSR build/parse */
function buildCSR({ privateKeyPem, subjectDer, spkiDer, sanList }){
  let attrs = Buffer.from([0xa0,0x00]); // [0] empty
  if (sanList && sanList.length){
    const sanExt = extSAN(sanList);
    const extSeq = SEQ(sanExt);
    const attr   = SEQ(OID(O.pkcs9.extensionRequest), SET(extSeq));
    const setAll = SET(attr);
    attrs = Buffer.concat([Buffer.from([0xa0]), derLen(setAll.length-2), setAll.slice(2)]);
  }
  const cri = SEQ(INTi(0), subjectDer, spkiDer, attrs);
  const keyObj = crypto.createPrivateKey(privateKeyPem);
  const sig = crypto.sign('sha256', cri, keyObj);
  const sigAlg = csrSigAlgForKeyObject(keyObj);
  return SEQ(cri, sigAlg, BIT(sig,0));
}
function parseCSR(csrPem){
  const der=fromPEM(csrPem,'CERTIFICATE REQUEST');
  const top=readTLV(der,0); if(top.tag!==T.SEQ) throw new Error('CSR top not SEQ');
  const cri=readTLV(der,top.start); if(cri.tag!==T.SEQ) throw new Error('CRI not SEQ');
  let p=cri.start; p=readTLV(der,p).end; // version
  const subj=readTLV(der,p); if(subj.tag!==T.SEQ) throw new Error('subject not SEQ'); const subjectDer=der.slice(subj.start,subj.end); p=subj.end;
  const spki=readTLV(der,p); if(spki.tag!==T.SEQ) throw new Error('spki not SEQ'); const spkiDer=der.slice(spki.start,spki.end); p=spki.end;
  let san=[]; if(p<cri.end){ const attrs=readTLV(der,p); let a=attrs.start; while(a<attrs.end){ const attr=readTLV(der,a); const s1=readTLV(der,attr.start); const oid=readTLV(der,s1.start); const name=oidToString(der.slice(oid.start,oid.end)); const set=readTLV(der,oid.end);
    if(name===O.pkcs9.extensionRequest){ const exts=readTLV(der,set.start); let e=exts.start; while(e<exts.end){ const ext=readTLV(der,e); const ex=readTLV(der,ext.start); const eo=readTLV(der,ex.start); const ename=oidToString(der.slice(eo.start,eo.end)); let c=eo.end; if(der[c]===0x01) c=readTLV(der,c).end; const oct=readTLV(der,c);
      if(ename===O.ext.subjectAltName){ const gns=readTLV(der,oct.start); let g=gns.start; while(g<gns.end){ const tag=der[g]; const {len,hdr}=readLen(der,g+1); const s=der.slice(g+1+hdr,g+1+hdr+len);
        if(tag===0x82) san.push(`DNS:${s.toString('ascii')}`); else if(tag===0x81) san.push(`email:${s.toString('ascii')}`); else if(tag===0x87) san.push(`IP:${Array.from(s).join('.')}`);
        g=g+1+hdr+len; } } e=ext.end; } }
    a=attr.end; } }
  return { subjectDer, spkiDer, san };
}

function parseOCSPRequest(der){
  const buf = Buffer.isBuffer(der) ? der : Buffer.from(der);
  const top = readTLV(buf,0);
  if(top.tag !== T.SEQ) throw new Error('OCSP request top not SEQ');
  const tbs = readTLV(buf, top.start);
  if(tbs.tag !== T.SEQ) throw new Error('OCSP TBS not SEQ');
  let p = tbs.start;
  let version = 0;
  let tlv = readTLV(buf,p);
  if(tlv.tag === 0xa0){
    const ver = readTLV(buf, tlv.start);
    if(ver.tag !== T.INT) throw new Error('OCSP version not INT');
    version = Number(bufToBigInt(buf.slice(ver.start, ver.end)));
    p = tlv.end;
    if(p < tbs.end) tlv = readTLV(buf,p);
  }
  if(tlv && tlv.tag === 0xa1){
    p = tlv.end;
    if(p < tbs.end) tlv = readTLV(buf,p);
  }
  if(!tlv || tlv.tag !== T.SEQ) throw new Error('OCSP requestList missing');
  const requestList = tlv;
  p = requestList.start;
  const requests = [];
  while(p < requestList.end){
    const req = readTLV(buf,p);
    if(req.tag !== T.SEQ) throw new Error('OCSP request entry not SEQ');
    let q = req.start;
    const certIdTLV = readTLV(buf,q);
    if(certIdTLV.tag !== T.SEQ) throw new Error('OCSP CertID not SEQ');
    const certIdDer = Buffer.from(buf.slice(q, q + certIdTLV.total));
    let ci = certIdTLV.start;
    const hashAlgTLV = readTLV(buf,ci);
    if(hashAlgTLV.tag !== T.SEQ) throw new Error('OCSP hashAlgorithm not SEQ');
    const hashAlgOID = readTLV(buf, hashAlgTLV.start);
    const hashAlgorithm = oidToString(buf.slice(hashAlgOID.start, hashAlgOID.end));
    ci = hashAlgTLV.end;
    const issuerNameHashTLV = readTLV(buf,ci);
    if(issuerNameHashTLV.tag !== T.OCT) throw new Error('OCSP issuerNameHash not OCT');
    const issuerNameHash = Buffer.from(buf.slice(issuerNameHashTLV.start, issuerNameHashTLV.end));
    ci = issuerNameHashTLV.end;
    const issuerKeyHashTLV = readTLV(buf,ci);
    if(issuerKeyHashTLV.tag !== T.OCT) throw new Error('OCSP issuerKeyHash not OCT');
    const issuerKeyHash = Buffer.from(buf.slice(issuerKeyHashTLV.start, issuerKeyHashTLV.end));
    ci = issuerKeyHashTLV.end;
    const serialTLV = readTLV(buf,ci);
    if(serialTLV.tag !== T.INT) throw new Error('OCSP serial not INT');
    const serialBuf = Buffer.from(buf.slice(serialTLV.start, serialTLV.end));
    requests.push({
      certIdDer,
      hashAlgorithm,
      issuerNameHash,
      issuerKeyHash,
      serialBuf,
      serialHex: bufToHex(serialBuf)
    });
    p = req.end;
  }
  let extensions = {};
  const afterList = requestList.end;
  if(afterList < tbs.end){
    const extWrapper = readTLV(buf, afterList);
    if(extWrapper.tag === 0xa2){
      const extSeq = readTLV(buf, extWrapper.start);
      let extPos = extSeq.start;
      while(extPos < extSeq.end){
        const extTLV = readTLV(buf, extPos);
        extPos = extTLV.end;
        const oidTLV = readTLV(buf, extTLV.start);
        const oid = oidToString(buf.slice(oidTLV.start, oidTLV.end));
        let valuePos = oidTLV.end;
        if(valuePos < extTLV.end){
          const maybeBool = readTLV(buf, valuePos);
          if(maybeBool.tag === 0x01){
            valuePos = maybeBool.end;
          }
        }
        if(valuePos >= extTLV.end) continue;
        const valTLV = readTLV(buf, valuePos);
        if(valTLV.tag !== T.OCT) continue;
        const raw = Buffer.from(buf.slice(valTLV.start, valTLV.end));
        if(oid === O.ocsp.nonce){
          let nonceValue = raw;
          try {
            const inner = readTLV(raw, 0);
            if(inner.tag === T.OCT && inner.end === raw.length){
              nonceValue = Buffer.from(raw.slice(inner.start, inner.end));
            }
          } catch {}
          extensions.nonce = nonceValue;
        }
      }
    }
  }
  return { version, requests, extensions };
}
function oidToString(oidDer){ const b=oidDer; if(!b.length) return ''; const first=Math.floor(b[0]/40), second=b[0]%40; const out=[first,second]; let v=0n; for(let i=1;i<b.length;i++){ v=(v<<7n)|BigInt(b[i]&0x7f); if((b[i]&0x80)===0){ out.push(Number(v)); v=0n; } } return out.join('.'); }

/* ============ Core Class ============ */
class CertificateAuthoritySystem {
  constructor(baseDir, options = {}){
    this.baseDir = baseDir;
    this.caDir   = path.join(baseDir,'ca');
    this.usersDir= path.join(baseDir,'users');
    this.crlDir = path.join(this.caDir,'crl');
    this.ocspDir = path.join(this.caDir,'ocsp');
    this.paths = {
      key: path.join(this.caDir,'root_key.pem'),
      cert: path.join(this.caDir,'root_cert.pem'),
      config: path.join(this.caDir,'config.json'),
      crlPem: path.join(this.crlDir,'crl.pem'),
      crlDer: path.join(this.crlDir,'crl.der'),
      ocspRequest: path.join(this.ocspDir,'ocsp_req.der'),
      ocspResponse: path.join(this.ocspDir,'ocsp_res.der')
    };
    this.usersFilePath = null;
    this._issuerDerCache = null;
    this._configCache = null;

    const builtInSubjectDefaults = {
      C: 'TR',
      ST: 'Sivas',
      L: 'Merkez',
      O: 'Fitfak',
      OU: 'Fitfak Application'
    };

    if (Object.prototype.hasOwnProperty.call(options, 'subjectDefaults')) {
      this.subjectDefaults = pruneObject(Object.assign({}, options.subjectDefaults || {}));
    } else {
      this.subjectDefaults = pruneObject(Object.assign({}, builtInSubjectDefaults));
    }

    this._ensureLayout();
  }

  /* --- Root CA oluştur --- */
  initRoot(subjectJson, { days=900, ecPrivateKeyFormat='pkcs8', services=null }={}){
    this._ensureLayout();

    const privExport = ecPrivateKeyFormat==='sec1'
      ? { type:'sec1', format:'pem' }   // "BEGIN EC PRIVATE KEY"
      : { type:'pkcs8', format:'pem' }; // "BEGIN PRIVATE KEY"

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve:'prime256v1',
      publicKeyEncoding: { type:'spki', format:'pem' },
      privateKeyEncoding: privExport
    });

    const subjectDer = subjectFromJSON(subjectJson);
    const issuerDer  = subjectDer;
    const spkiDer    = fromPEM(publicKey,'PUBLIC KEY');

    const notBefore=new Date(), notAfter=new Date(notBefore.getTime()+days*86400e3);
    const serialBuf = randPos(16);
    const ski = sha1(spkiSubjectBits(spkiDer));

    const exts = wrapExts([
      extBasicConstraints({ ca:true, pathLen:0, critical:true }),
      extKeyUsage({ keyCertSign:true, cRLSign:true, critical:true }),
      extSKI(ski)
    ]);

    const signerKind = 'EC';
    const tbs = buildTBS({ serialBuf, issuerDer, subjectDer, spkiDer, notBefore, notAfter, extensionsDer: exts, signerKind });
    const certDer = signCert(tbs, privateKey, signerKind);
    const certPem = toPEM(certDer,'CERTIFICATE');

    // Parse guard
    new X509Certificate(certPem);

    atomicWrite(this.paths.key, privateKey);
    atomicWrite(this.paths.cert, certPem);
    this._issuerDerCache = subjectDer;

    const createdAt = new Date().toISOString();
    const cfg = this._loadConfig();
    this._saveConfig({
      ...cfg,
      subjectJson,
      keyType:'EC',
      curve:'prime256v1',
      ecPrivateKeyFormat,
      createdAt,
      services: services ? { ...cfg.services, ...services } : cfg.services
    });

    return { keyPath:this.paths.key, certPath:this.paths.cert, configPath:this.paths.config, keyType:'EC', certPem, created:true };
  }

  rootExists(){
    return fs.existsSync(this.paths.key) && fs.existsSync(this.paths.cert);
  }

  ensureRoot(subjectJson=null, options={}){
    this._ensureLayout();
    const haveRoot = this.rootExists();
    const { services=null, ...initOptions } = options || {};

    if(haveRoot){
      const certPem = readIf(this.paths.cert, null);
      const cfg = this._loadConfig();
      const mergedServices = services && typeof services === 'object'
        ? { ...cfg.services, ...services }
        : cfg.services;
      const updated = {
        ...cfg,
        services: mergedServices
      };
      if(subjectJson){
        updated.subjectJson = subjectJson;
      }
      if(initOptions.ecPrivateKeyFormat){
        updated.ecPrivateKeyFormat = initOptions.ecPrivateKeyFormat;
      }
      if(!updated.createdAt){
        updated.createdAt = new Date().toISOString();
      }
      this._saveConfig(updated);
      return {
        created:false,
        keyPath:this.paths.key,
        certPath:this.paths.cert,
        certPem,
        config:updated,
        configPath:this.paths.config
      };
    }

    if(!subjectJson){
      throw new Error('Root CA yok. Oluşturmak için subjectJson gerekli.');
    }

    return this.initRoot(subjectJson, { ...initOptions, services });
  }

  /* --- Kullanıcı için key/CSR/cert üret --- */

  issueForUser(user, { days=90, san=[], subjectMap=null, ecPrivateKeyFormat='pkcs8', reuseThresholdDays=null, forceRenew=false, eku=null }={}){
    const caKeyPem = readIf(this.paths.key), caCertPem = readIf(this.paths.cert);
    if(!caKeyPem || !caCertPem) throw new Error('Root CA yok. Önce initRoot.');

    const config = this._loadConfig();
    const data = this._loadUsersData();
    const emailOriginal = user && user.email ? String(user.email).trim() : null;
    const emailLower = emailOriginal ? emailOriginal.toLowerCase() : null;
    if(!emailLower) throw new Error('Kullanıcı e-posta adresi gerekli');

    let index = null;
    let record = null;
    if(user && user.id && data.byId.has(String(user.id))){
      index = data.byId.get(String(user.id));
      record = data.users[index];
    } else if(emailLower && data.byEmail.has(emailLower)){
      index = data.byEmail.get(emailLower);
      record = data.users[index];
    }

    if(record){
      record = { ...record };
    } else {
      const generatedId = user && user.id ? String(user.id) : 'user-' + randPos(4).toString('hex');
      record = { id: generatedId, revocations: [], certificate: null };
      data.users.push(record);
      index = data.users.length - 1;
    }

    const updatable = ['name','surname','C','ST','L','O','OU'];
    for(const key of updatable){
      if(user && Object.prototype.hasOwnProperty.call(user, key) && user[key] != null){
        record[key] = user[key];
      }
    }
    record.id = record.id || (user && user.id ? String(user.id) : 'user-' + randPos(4).toString('hex'));
    record.email = emailOriginal;
    this._ensureUserShape(record);

    const windowDays = reuseThresholdDays != null ? reuseThresholdDays : (config.autoRenewThresholdDays ?? DEFAULT_CONFIG.autoRenewThresholdDays);
    const thresholdMs = windowDays != null ? windowDays * 86400e3 : null;
    const nowMs = Date.now();

    if(!forceRenew && record.certificate && record.certificate.serial && !record.certificate.revokedAt){
      const notAfter = record.certificate.notAfter ? new Date(record.certificate.notAfter) : null;
      if(notAfter && !Number.isNaN(notAfter.valueOf()) && notAfter.getTime() > nowMs){
        const diff = notAfter.getTime() - nowMs;
        if(thresholdMs == null || diff > thresholdMs){
          const certPath = record.certificate.certPath;
          if(certPath && fs.existsSync(certPath)){
            data.users[index] = record;
            this._saveUsersData(data);
            const keyPem = record.certificate.keyPath ? readIf(record.certificate.keyPath, null) : null;
            const pubPem = record.certificate.publicKeyPath ? readIf(record.certificate.publicKeyPath, null) : null;
            const csrPem = record.certificate.csrPath ? readIf(record.certificate.csrPath, null) : null;
            const certPem = readIf(certPath, null);
            return {
              keyPath: record.certificate.keyPath || null,
              certPath,
              csrPath: record.certificate.csrPath || null,
              privateKeyPem: keyPem,
              publicKeyPem: pubPem,
              certPem,
              csrPem,
              serialHex: sanitizeHexString(record.certificate.serial),
              reused:true
            };
          }
        }
      }
    }

    const udir=path.join(this.usersDir, record.id);
    const keysDir=path.join(udir,'keys');
    const csrsDir=path.join(udir,'csrs');
    const certsDir=path.join(udir,'certs');
    ensureDir(keysDir); ensureDir(csrsDir); ensureDir(certsDir);

    const privExport = ecPrivateKeyFormat==='sec1' ? { type:'sec1', format:'pem' } : { type:'pkcs8', format:'pem' };

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve:'prime256v1',
      publicKeyEncoding: { type:'spki', format:'pem' },
      privateKeyEncoding: privExport
    });

    const subj = subjectMap
      ? subjectMap({ ...record, email: emailOriginal })
      : this._defaultSubjectFor(record, emailOriginal);
    const subjectDer = subjectFromJSON(subj);
    const issuerDer = this._issuerDER(caCertPem);
    const spkiDer = fromPEM(publicKey,'PUBLIC KEY');

    const usedSerials = this._collectUsedSerials(data.users);
    const { buf:serialBuf, hex:serialHex } = this._allocateSerial(usedSerials);
    const notBefore=new Date();
    const notAfter=new Date(notBefore.getTime()+days*86400e3);

    const sanFinal = Array.from(new Set([
      ...san,
      ...(emailOriginal ? [`email:${emailOriginal}`] : []),
      ...(subj.CN && isHostname(subj.CN) ? [`DNS:${subj.CN}`] : [])
    ]));

    const caX = new X509Certificate(caCertPem);
    const caSpkiDer = caX.publicKey.export({ type:'spki', format:'der' });
    const caSKI = sha1(spkiSubjectBits(caSpkiDer));
    const leafSKI = sha1(spkiSubjectBits(spkiDer));

    const ku = extKeyUsage({ digitalSignature:true, critical:true });
    const ekuList = Array.isArray(eku) && eku.length ? eku : ['codeSigning'];
    const ekuExt = ekuList.length ? extEKU({ usages: ekuList, critical:false }) : null;
    const aiaExt = extAuthorityInfoAccess({ ocspUrl: config.services.ocspUrl || config.ocspUrl, caIssuersUrl: config.services.caIssuersUrl || config.caIssuersUrl });

    const exts = wrapExts([
      extBasicConstraints({ ca:false, critical:true }),
      ku,
      ekuExt,
      sanFinal.length ? extSAN(sanFinal) : null,
      (config.services.crlUrl || config.crlUrl) ? extCRLDistributionPoints([config.services.crlUrl || config.crlUrl]) : null,
      aiaExt,
      extSKI(leafSKI),
      extAKI(caSKI)
    ]);

    const signerKind = 'EC';
    const certDer = signCert(
      buildTBS({ serialBuf, issuerDer, subjectDer, spkiDer, notBefore, notAfter, extensionsDer: exts, signerKind }),
      caKeyPem, signerKind
    );
    const certPem = toPEM(certDer,'CERTIFICATE');
    this._sanityCheckCertWithCA(certPem, caCertPem);

    const keyPath = path.join(keysDir,'key.pem');
    const pubPath = path.join(keysDir,'pub.pem');
    const csrPath = path.join(csrsDir,'request.csr.pem');
    const certPath = path.join(certsDir,'cert.pem');

    atomicWrite(keyPath, privateKey);
    atomicWrite(pubPath, publicKey);

    const csrDer = buildCSR({ privateKeyPem: privateKey, subjectDer, spkiDer, sanList: sanFinal });
    const csrPem = toPEM(csrDer,'CERTIFICATE REQUEST');
    atomicWrite(csrPath, csrPem);
    atomicWrite(certPath, certPem);

    const previous = record.certificate && record.certificate.serial ? sanitizeHexString(record.certificate.serial) : null;
    if(previous){
      const nowIso = new Date().toISOString();
      if(!Array.isArray(record.revocations)) record.revocations = [];
      const already = record.revocations.find(entry => sanitizeHexString(entry.serial) === previous);
      if(!already){
        record.revocations.push({
          serial: previous,
          revokedAt: nowIso,
          reason: 'superseded'
        });
      }
    }

    record.certificate = pruneObject({
      serial: serialHex,
      issuedAt: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      certPath,
      csrPath,
      keyPath,
      publicKeyPath: pubPath
    });

    this._ensureUserShape(record);
    data.users[index] = record;
    this._saveUsersData(data);

    return { keyPath, certPath, csrPath, privateKeyPem:privateKey, publicKeyPem:publicKey, certPem, csrPem, serialHex, created:true };
  }
  /* --- Dış CSR’den sertifika üret --- */

  issueFromCSRForUser(user, csrPem, { days=90, sanOverride=null, eku=null }={}){
    const caKeyPem = readIf(this.paths.key), caCertPem = readIf(this.paths.cert);
    if(!caKeyPem || !caCertPem) throw new Error('Root CA yok. Önce initRoot.');

    const { subjectDer, spkiDer, san } = parseCSR(csrPem);
    const config = this._loadConfig();
    const data = this._loadUsersData();

    const emailOriginal = user && user.email ? String(user.email).trim() : null;
    const emailLower = emailOriginal ? emailOriginal.toLowerCase() : null;

    let index = null;
    let record = null;
    if(user && user.id && data.byId.has(String(user.id))){
      index = data.byId.get(String(user.id));
      record = data.users[index];
    } else if(emailLower && data.byEmail.has(emailLower)){
      index = data.byEmail.get(emailLower);
      record = data.users[index];
    }

    if(record){
      record = { ...record };
    } else {
      const generatedId = user && user.id ? String(user.id) : (emailLower ? `user-${emailLower}` : 'user-' + randPos(4).toString('hex'));
      record = { id: generatedId, revocations: [], certificate: null };
      data.users.push(record);
      index = data.users.length - 1;
    }

    const updatable = ['name','surname','C','ST','L','O','OU'];
    for(const key of updatable){
      if(user && Object.prototype.hasOwnProperty.call(user, key) && user[key] != null){
        record[key] = user[key];
      }
    }
    record.id = record.id || (user && user.id ? String(user.id) : (emailLower ? `user-${emailLower}` : 'user-' + randPos(4).toString('hex')));
    record.email = emailOriginal;
    this._ensureUserShape(record);

    const issuerDer = this._issuerDER(caCertPem);
    const usedSerials = this._collectUsedSerials(data.users);
    const { buf:serialBuf, hex:serialHex } = this._allocateSerial(usedSerials);
    const notBefore=new Date();
    const notAfter=new Date(notBefore.getTime()+days*86400e3);

    const caX = new X509Certificate(caCertPem);
    const caSpkiDer = caX.publicKey.export({ type:'spki', format:'der' });
    const caSKI = sha1(spkiSubjectBits(caSpkiDer));
    const leafSKI = sha1(spkiSubjectBits(spkiDer));

    const ku = this._kuFromSpki(spkiDer);
    const ekuList = Array.isArray(eku) && eku.length ? eku : ['codeSigning'];
    const ekuExt = ekuList.length ? extEKU({ usages: ekuList, critical:false }) : null;
    const aiaExt = extAuthorityInfoAccess({ ocspUrl: config.services.ocspUrl || config.ocspUrl, caIssuersUrl: config.services.caIssuersUrl || config.caIssuersUrl });

    const finalSAN = Array.from(new Set(sanOverride ?? san ?? []));
    if(emailOriginal && !finalSAN.some(item => item && item.toLowerCase().startsWith('email:'))){
      finalSAN.push(`email:${emailOriginal}`);
    }

    const exts = wrapExts([
      extBasicConstraints({ ca:false, critical:true }),
      ku,
      ekuExt,
      finalSAN.length ? extSAN(finalSAN) : null,
      (config.services.crlUrl || config.crlUrl) ? extCRLDistributionPoints([config.services.crlUrl || config.crlUrl]) : null,
      aiaExt,
      extSKI(leafSKI),
      extAKI(caSKI)
    ]);

    const signerKind=this._signerKind(caKeyPem);
    const certDer = signCert(
      buildTBS({ serialBuf, issuerDer, subjectDer, spkiDer, notBefore, notAfter, extensionsDer: exts, signerKind }),
      caKeyPem, signerKind
    );
    const certPem = toPEM(certDer,'CERTIFICATE');

    this._sanityCheckCertWithCA(certPem, caCertPem);

    const udir=path.join(this.usersDir, record.id), certsDir=path.join(udir,'certs'); ensureDir(certsDir);
    const certPath = path.join(certsDir,'cert_from_csr.pem');
    atomicWrite(certPath, certPem);

    const previous = record.certificate && record.certificate.serial ? sanitizeHexString(record.certificate.serial) : null;
    if(previous){
      const nowIso = new Date().toISOString();
      if(!Array.isArray(record.revocations)) record.revocations = [];
      const already = record.revocations.find(entry => sanitizeHexString(entry.serial) === previous);
      if(!already){
        record.revocations.push({
          serial: previous,
          revokedAt: nowIso,
          reason: 'superseded'
        });
      }
    }

    record.certificate = pruneObject({
      serial: serialHex,
      issuedAt: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      certPath,
      san: finalSAN
    });

    this._ensureUserShape(record);
    data.users[index] = record;
    this._saveUsersData(data);

    return { certPem, certPath, serialHex, created:true };
  }
  /* --- users.json toplu --- */

  processUsersJSON(usersJsonPath, opts={}){
    if(!usersJsonPath) throw new Error('users.json yolu gerekli');
    const resolved = path.resolve(usersJsonPath);
    this.setUsersFile(resolved);
    const arr = JSON.parse(fs.readFileSync(resolved,'utf8'));
    if(!Array.isArray(arr)) throw new Error('users.json must be an array');

    const out=[];
    const seenEmails = new Set();
    const seenIds = new Set();

    for(const u of arr){
      const userId = u && u.id ? String(u.id) : null;
      if(!u || !userId){ out.push({ ok:false, error:'missing id' }); continue; }
      if(seenIds.has(userId)){ out.push({ ok:false, id:userId, error:`duplicate id in users.json: ${userId}` }); continue; }
      seenIds.add(userId);

      const email = u.email ? String(u.email).trim().toLowerCase() : null;
      if(!email){ out.push({ ok:false, id:userId, error:'email gerekli' }); continue; }
      if(seenEmails.has(email)){ out.push({ ok:false, id:userId, error:`duplicate email in users.json: ${email}` }); continue; }
      seenEmails.add(email);

      try {
        const result = this.issueForUser(u, opts);
        out.push({ ok:true, id:userId, cert:result.certPath, key:result.keyPath, csr:result.csrPath, serial:result.serialHex, reused:!!result.reused });
      } catch (e) {
        out.push({ ok:false, id:userId, error:e.message });
      }
    }

    return out;
  }


  configureServices({ ocspUrl=null, crlUrl=null, caIssuersUrl=null, ocspNextUpdateSeconds=null, crlNextUpdateSeconds=null, autoRenewThresholdDays=null }={}){
    const cfg = this._loadConfig();
    const next = { ...cfg, services: { ...cfg.services } };
    if(ocspUrl !== null) next.services.ocspUrl = ocspUrl;
    if(crlUrl !== null) next.services.crlUrl = crlUrl;
    if(caIssuersUrl !== null) next.services.caIssuersUrl = caIssuersUrl;
    if(ocspNextUpdateSeconds !== null) next.ocspNextUpdateSeconds = ocspNextUpdateSeconds;
    if(crlNextUpdateSeconds !== null) next.crlNextUpdateSeconds = crlNextUpdateSeconds;
    if(autoRenewThresholdDays !== null) next.autoRenewThresholdDays = autoRenewThresholdDays;
    this._saveConfig(next);
    return this._loadConfig();
  }

  getConfig(){
    return this._loadConfig();
  }

  setUsersFile(usersJsonPath){
    if(!usersJsonPath){
      this.usersFilePath = null;
      return;
    }
    const resolved = path.resolve(usersJsonPath);
    this.usersFilePath = resolved;
  }

  getRegistry(){
    const data = this._loadUsersData();
    return {
      users: JSON.parse(JSON.stringify(data.users)),
      revoked: this._collectRevocationEntries(data.users)
    };
  }

  listRevoked(){
    const data = this._loadUsersData();
    return this._collectRevocationEntries(data.users);
  }

  autoRenewExpiring({ thresholdDays=null, days=null, eku=null }={}){
    const config = this._loadConfig();
    const data = this._loadUsersData();
    const windowDays = thresholdDays != null ? thresholdDays : (config.autoRenewThresholdDays ?? DEFAULT_CONFIG.autoRenewThresholdDays);
    const thresholdMs = windowDays != null ? windowDays * 86400e3 : null;
    const now = Date.now();
    const renewed = [];

    for(const user of data.users){
      if(!user || typeof user !== 'object') continue;
      if(!user.certificate || !user.certificate.serial) continue;
      if(user.certificate.revokedAt) continue;
      const notAfter = user.certificate.notAfter ? new Date(user.certificate.notAfter) : null;
      if(!notAfter || Number.isNaN(notAfter.valueOf())) continue;
      const diff = notAfter.getTime() - now;
      if(diff <= 0) continue;
      if(thresholdMs != null && diff > thresholdMs) continue;

      const validityMs = user.certificate.issuedAt ? (notAfter.getTime() - new Date(user.certificate.issuedAt).getTime()) : diff;
      const validityDays = days != null ? days : Math.max(1, Math.round(validityMs / 86400e3));
      const sanList = Array.isArray(user.certificate.san) ? user.certificate.san.slice() : [];
      const ecFormat = user.certificate.ecPrivateKeyFormat || 'pkcs8';
      try {
        const result = this.issueForUser(user, {
          days: validityDays,
          san: sanList,
          ecPrivateKeyFormat: ecFormat,
          forceRenew:true,
          reuseThresholdDays:0,
          eku
        });
        renewed.push({ previousSerial: user.certificate.serial, newSerial: result.serialHex, certPath: result.certPath });
      } catch (err) {
        renewed.push({ previousSerial: user.certificate.serial, error: err.message });
      }
    }

    return renewed;
  }



  revokeByEmail(email, { reason='unspecified', revokedAt=null }={}){
    if(!email) throw new Error('email gerekli');
    const targetEmail = String(email).trim().toLowerCase();
    if(!targetEmail) throw new Error('email gerekli');

    const data = this._loadUsersData();
    if(!data.byEmail.has(targetEmail)) return [];
    const index = data.byEmail.get(targetEmail);
    const user = { ...data.users[index] };
    this._ensureUserShape(user);

    if(!user.certificate || !user.certificate.serial) return [];
    if(user.certificate.revokedAt) return [];

    const reasonKey = CRL_REASON_MAP.hasOwnProperty(reason) ? reason : 'unspecified';
    let stamp = revokedAt ? new Date(revokedAt) : new Date();
    if(Number.isNaN(stamp.valueOf())) stamp = new Date();
    const revokedAtIso = stamp.toISOString();

    user.certificate.revokedAt = revokedAtIso;
    user.certificate.revocationReason = reasonKey;
    if(!Array.isArray(user.revocations)) user.revocations = [];
    const serialHex = sanitizeHexString(user.certificate.serial);
    const already = user.revocations.find(entry => sanitizeHexString(entry.serial) === serialHex);
    if(!already){
      user.revocations.push({
        serial: serialHex,
        revokedAt: revokedAtIso,
        reason: reasonKey
      });
    }

    this._ensureUserShape(user);
    data.users[index] = user;
    this._saveUsersData(data);

    try { this.generateCRL(); } catch {}

    return [{
      serialHex: sanitizeHexString(user.certificate.serial),
      userId: user.id || null,
      email: targetEmail,
      revokedAt: revokedAtIso,
      reason: reasonKey,
      reasonCode: CRL_REASON_MAP[reasonKey]
    }];
  }

  reactivateSerial(serial, { restoredAt=null }={}){
    if(!serial) throw new Error('serial gerekli');
    const hex = sanitizeHexString(serial);
    if(!hex) throw new Error('serial gerekli');

    const data = this._loadUsersData();
    const restored = [];
    let updated = false;

    for(let i=0; i<data.users.length; i++){
      const user = { ...data.users[i] };
      this._ensureUserShape(user);
      let changed = false;

      if(user.certificate && sanitizeHexString(user.certificate.serial) === hex){
        if(user.certificate.revokedAt){
          const stamp = restoredAt ? new Date(restoredAt) : new Date();
          const iso = Number.isNaN(stamp.valueOf()) ? new Date().toISOString() : stamp.toISOString();
          user.certificate.revokedAt = null;
          user.certificate.revocationReason = null;
          if(Array.isArray(user.revocations)){
            user.revocations = user.revocations.filter(item => sanitizeHexString(item.serial) !== hex);
          }
          this._ensureUserShape(user);
          data.users[i] = user;
          restored.push({ serialHex: hex, userId: user.id || null, email: user.email ? String(user.email).trim().toLowerCase() : null, restoredAt: iso });
          changed = true;
          updated = true;
        }
      } else if(Array.isArray(user.revocations)){
        const before = user.revocations.length;
        user.revocations = user.revocations.filter(item => sanitizeHexString(item.serial) !== hex);
        if(user.revocations.length !== before){
          this._ensureUserShape(user);
          data.users[i] = user;
          changed = true;
          updated = true;
        }
      }

      if(changed && !restored.length && user.certificate && sanitizeHexString(user.certificate.serial) === hex){
        const stamp = restoredAt ? new Date(restoredAt) : new Date();
        const iso = Number.isNaN(stamp.valueOf()) ? new Date().toISOString() : stamp.toISOString();
        restored.push({ serialHex: hex, userId: user.id || null, email: user.email ? String(user.email).trim().toLowerCase() : null, restoredAt: iso });
      }
    }

    if(updated){
      this._saveUsersData(data);
      try { this.generateCRL(); } catch {}
    }

    return restored;
  }

  reactivateByEmail(email, { restoredAt=null }={}){
    if(!email) throw new Error('email gerekli');
    const targetEmail = String(email).trim().toLowerCase();
    if(!targetEmail) throw new Error('email gerekli');

    const data = this._loadUsersData();
    if(!data.byEmail.has(targetEmail)) return [];
    const index = data.byEmail.get(targetEmail);
    const user = data.users[index];
    if(!user || !user.certificate || !user.certificate.serial) return [];

    return this.reactivateSerial(user.certificate.serial, { restoredAt });
  }



  generateCRL({ thisUpdate=new Date(), nextUpdate=null }={}){
    const caKeyPem = readIf(this.paths.key);
    const caCertPem = readIf(this.paths.cert);
    if(!caKeyPem || !caCertPem) throw new Error('Root CA yok. Önce initRoot.');

    const config = this._loadConfig();
    const data = this._loadUsersData();
    const revocations = this._collectRevocationEntries(data.users);

    const signerKind = this._signerKind(caKeyPem);
    const issuerDer = this._issuerDER(caCertPem);
    const caX = new X509Certificate(caCertPem);
    const caSpkiDer = caX.publicKey.export({ type:'spki', format:'der' });
    const caSKI = sha1(spkiSubjectBits(caSpkiDer));

    const now = thisUpdate instanceof Date ? thisUpdate : new Date(thisUpdate);
    const next = nextUpdate
      ? (nextUpdate instanceof Date ? nextUpdate : new Date(nextUpdate))
      : new Date(now.getTime() + (config.crlNextUpdateSeconds || DEFAULT_CONFIG.crlNextUpdateSeconds) * 1000);

    const sortedRevocations = revocations
      .map(entry => ({ ...entry, serialHex: sanitizeHexString(entry.serialHex) }))
      .filter(entry => entry.serialHex)
      .sort((a,b) => (a.revokedAt || '').localeCompare(b.revokedAt || ''));

    const revokedSeq = sortedRevocations.length ? SEQ(...sortedRevocations.map(info => {
      const serial = info.serialHex.length % 2 ? `0${info.serialHex}` : info.serialHex;
      const serialBuf = Buffer.from(serial, 'hex');
      const serialInt = INTpos(serialBuf);
      const revTime = derTime(new Date(info.revokedAt || now));
      const reasonCode = info.reasonCode != null ? info.reasonCode : (info.reason && CRL_REASON_MAP[info.reason]);
      const reasonExt = reasonCode != null ? crlReasonExtension(reasonCode) : null;
      const parts = [serialInt, revTime];
      if(reasonExt){
        parts.push(SEQ(reasonExt));
      }
      return SEQ(...parts);
    })) : null;

    const sigAlg = algIdForSigner(signerKind);
    const exts = [extAKI(caSKI)].filter(Boolean);
    const extWrap = exts.length ? wrap(0xa0, SEQ(...exts)) : null;

    const tbsParts = [
      INTi(1),
      sigAlg,
      issuerDer,
      derTime(now),
      derTime(next)
    ];
    if(revokedSeq) tbsParts.push(revokedSeq);
    if(extWrap) tbsParts.push(extWrap);

    const tbs = SEQ(...tbsParts);
    const signature = crypto.sign('sha256', tbs, caKeyPem);
    const crl = SEQ(tbs, sigAlg, BIT(signature,0));

    const crlDer = crl;
    const crlPem = toPEM(crlDer, 'X509 CRL');
    atomicWrite(this.paths.crlDer, crlDer);
    atomicWrite(this.paths.crlPem, crlPem);
    return { crlDer, crlPem, thisUpdate: now, nextUpdate: next };
  }


  latestCRL(){
    try {
      const der = fs.readFileSync(this.paths.crlDer);
      return { der, pem: fs.readFileSync(this.paths.crlPem,'utf8') };
    } catch {
      return null;
    }
  }


  buildOCSPResponse(requestDer){
    const caKeyPem = readIf(this.paths.key);
    const caCertPem = readIf(this.paths.cert);
    if(!caKeyPem || !caCertPem) throw new Error('Root CA yok. Önce initRoot.');

    let parsed;
    try {
      parsed = parseOCSPRequest(requestDer);
    } catch (err) {
      return { ok:false, status:'malformedRequest', der:this._ocspError('malformedRequest'), error:err };
    }
    if(!parsed.requests.length){
      return { ok:false, status:'malformedRequest', der:this._ocspError('malformedRequest'), error:new Error('OCSP request list boş') };
    }

    const issuerDer = this._issuerDER(caCertPem);
    const issuerNameHash = sha1(issuerDer);
    const caX = new X509Certificate(caCertPem);
    const spkiDer = caX.publicKey.export({ type:'spki', format:'der' });
    const issuerKeyHash = sha1(spkiSubjectBits(spkiDer));
    const config = this._loadConfig();
    const data = this._loadUsersData();

    const revokedEntries = this._collectRevocationEntries(data.users);
    const revokedMap = new Map();
    for(const entry of revokedEntries){
      if(!entry) continue;
      const hex = sanitizeHexString(entry.serialHex);
      if(hex) revokedMap.set(hex, entry);
    }

    const activeMap = new Map();
    for(const user of data.users){
      if(!user || typeof user !== 'object') continue;
      if(!user.certificate || !user.certificate.serial) continue;
      const hex = sanitizeHexString(user.certificate.serial);
      if(!hex) continue;
      activeMap.set(hex, { user, cert: user.certificate });
    }

    const now = new Date();
    const producedAt = generalizedTime(now);
    const nextUpdate = new Date(now.getTime() + (config.ocspNextUpdateSeconds || DEFAULT_CONFIG.ocspNextUpdateSeconds) * 1000);
    const nextUpdateGT = generalizedTime(nextUpdate);
    const thisUpdateGT = generalizedTime(now);

    const requestNonce = parsed.extensions && parsed.extensions.nonce ? Buffer.from(parsed.extensions.nonce) : null;
    const responses=[];
    for(const req of parsed.requests){
      const algo = req.hashAlgorithm;
      if(algo !== O.alg.sha1 && algo !== '1.3.14.3.2.26'){
        return { ok:false, status:'malformedRequest', der:this._ocspError('malformedRequest'), error:new Error('Unsupported hash algorithm') };
      }
      if(req.issuerNameHash.length !== issuerNameHash.length || !req.issuerNameHash.equals(issuerNameHash) || !req.issuerKeyHash.equals(issuerKeyHash)){
        return { ok:false, status:'unauthorized', der:this._ocspError('unauthorized'), error:new Error('Issuer hash mismatch') };
      }

      const serialHex = sanitizeHexString(bufToHex(req.serialBuf));
      const revoked = serialHex ? revokedMap.get(serialHex) : null;
      const issued = serialHex ? activeMap.get(serialHex) : null;

      let statusBuf;
      if(revoked){
        const revTime = new Date(revoked.revokedAt || now);
        const reasonCode = revoked.reasonCode != null ? revoked.reasonCode : (revoked.reason && CRL_REASON_MAP[revoked.reason]) || CRL_REASON_MAP.unspecified;
        const infoParts = [generalizedTime(revTime)];
        if(reasonCode != null){
          infoParts.push(wrap(0xa0, wrap(0x0a, Buffer.from([reasonCode]))));
        }
        statusBuf = wrap(0xa1, Buffer.concat(infoParts));
      } else if(issued){
        statusBuf = wrap(0x80, Buffer.alloc(0));
      } else {
        statusBuf = wrap(0x82, Buffer.alloc(0));
      }

      const single = SEQ(
        req.certIdDer,
        statusBuf,
        thisUpdateGT,
        wrap(0xa0, nextUpdateGT)
      );
      responses.push(single);
    }

    const responseSeq = SEQ(...responses);
    const responderID = wrap(0xa1, issuerDer);
    const responseExts = [];
    if(requestNonce){
      const nonceDer = wrap(T.OCT, requestNonce);
      responseExts.push(SEQ(OID(O.ocsp.nonce), Buffer.alloc(0), OCT(nonceDer)));
    }
    const responseDataParts = [responderID, producedAt, responseSeq];
    if(responseExts.length){
      responseDataParts.push(wrap(0xa1, SEQ(...responseExts)));
    }
    const responseData = SEQ(...responseDataParts);

    const signerKind = this._signerKind(caKeyPem);
    const sigAlg = algIdForSigner(signerKind);
    const signature = crypto.sign('sha256', responseData, caKeyPem);
    const certDer = fromPEM(caCertPem,'CERTIFICATE');
    const certsWrap = wrap(0xa0, SEQ(certDer));
    const basic = SEQ(responseData, sigAlg, BIT(signature,0), certsWrap);
    const respBytes = wrap(0xa0, SEQ(OID(O.ocsp.basicResponse), OCT(basic)));
    const final = SEQ(wrap(0x0a, Buffer.from([OCSP_RESPONSE_STATUS.successful])), respBytes);
    return { ok:true, status:'successful', der:final, producedAt:now, nextUpdate };
  }


  makeOCSPRequest(serial, { includeNonce=false, nonce=null }={}){
    const caCertPem = readIf(this.paths.cert);
    if(!caCertPem) throw new Error('Root CA yok. Önce initRoot.');

    let serialBuf;
    if(Buffer.isBuffer(serial)){
      serialBuf = Buffer.from(serial);
    } else if(typeof serial === 'string' || typeof serial === 'number'){
      let hex = typeof serial === 'number' ? serial.toString(16) : String(serial).replace(/[^0-9a-f]/gi,'');
      if(hex.length % 2) hex = `0${hex}`;
      serialBuf = Buffer.from(hex || '00', 'hex');
    } else if(serial && typeof serial.serialHex === 'string'){
      let hex = serial.serialHex;
      if(hex.length % 2) hex = `0${hex}`;
      serialBuf = Buffer.from(hex || '00', 'hex');
    } else {
      throw new Error('OCSP isteği için geçerli seri numarası gerekli');
    }
    if(!serialBuf.length) serialBuf = Buffer.from([0]);

    const issuerDer = this._issuerDER(caCertPem);
    const issuerNameHash = sha1(issuerDer);
    const caX = new X509Certificate(caCertPem);
    const spkiDer = caX.publicKey.export({ type:'spki', format:'der' });
    const issuerKeyHash = sha1(spkiSubjectBits(spkiDer));

    const hashAlg = SEQ(OID(O.alg.sha1), NULL());
    const certId = SEQ(hashAlg, OCT(issuerNameHash), OCT(issuerKeyHash), INTpos(serialBuf));
    const request = SEQ(certId);
    const requestList = SEQ(request);
    const tbsParts = [requestList];

    let nonceValue = null;
    if(includeNonce){
      nonceValue = Buffer.isBuffer(nonce) ? Buffer.from(nonce) : crypto.randomBytes(16);
      const nonceDer = wrap(T.OCT, nonceValue);
      const nonceExt = SEQ(OID(O.ocsp.nonce), Buffer.alloc(0), OCT(nonceDer));
      const extSeq = SEQ(nonceExt);
      tbsParts.push(wrap(0xa2, extSeq));
    }

    const tbs = SEQ(...tbsParts);
    const requestDer = SEQ(tbs);
    return { der:requestDer, nonce:nonceValue };
  }

  buildOCSPResponseForSerial(serial, options={}){
    const { der:requestDer } = this.makeOCSPRequest(serial, options);
    return this.buildOCSPResponse(requestDer);
  }

  buildOCSPErrorResponse(status){
    return { ok:false, status, der:this._ocspError(status) };
  }
  /* --- Zincir doğrulama & ECDH --- */
  verifyWithCA(certPem, caCertPem){ if(!isCertPEM(certPem)||!isCertPEM(caCertPem)) return false; const leaf=new X509Certificate(certPem); const ca=new X509Certificate(caCertPem); return leaf.verify(ca.publicKey); }
  static deriveSharedSecret(ownPrivPem, peerPubPem){ const priv=crypto.createPrivateKey(ownPrivPem), pub=crypto.createPublicKey(peerPubPem); return crypto.diffieHellman({ privateKey:priv, publicKey:pub }); }

  /* --- internals --- */
  _normalizeConfig(input){
    const base = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
    if(!input || typeof input !== 'object') return base;

    if(input.subjectJson && typeof input.subjectJson === 'object'){
      base.subjectJson = input.subjectJson;
    }
    if(typeof input.ecPrivateKeyFormat === 'string'){
      base.ecPrivateKeyFormat = input.ecPrivateKeyFormat === 'sec1' ? 'sec1' : 'pkcs8';
    }
    if(input.createdAt){
      const d = new Date(input.createdAt);
      if(!Number.isNaN(d.valueOf())) base.createdAt = d.toISOString();
    }
    if(input.services && typeof input.services === 'object'){
      const services = input.services;
      if(typeof services.ocspUrl === 'string') base.services.ocspUrl = services.ocspUrl || null;
      if(typeof services.crlUrl === 'string') base.services.crlUrl = services.crlUrl || null;
      if(typeof services.caIssuersUrl === 'string' && services.caIssuersUrl){
        base.services.caIssuersUrl = services.caIssuersUrl;
      }
    }
    if(Number.isFinite(input.ocspNextUpdateSeconds)){
      const v = Math.max(3600, Math.floor(input.ocspNextUpdateSeconds));
      base.ocspNextUpdateSeconds = v;
    }
    if(Number.isFinite(input.crlNextUpdateSeconds)){
      const v = Math.max(3600, Math.floor(input.crlNextUpdateSeconds));
      base.crlNextUpdateSeconds = v;
    }
    if(Number.isFinite(input.autoRenewThresholdDays)){
      const v = Math.max(0, Math.floor(input.autoRenewThresholdDays));
      base.autoRenewThresholdDays = v;
    }
    return base;
  }

  _loadConfig(){
    if(this._configCache){
      return JSON.parse(JSON.stringify(this._configCache));
    }
    this._ensureLayout();
    try {
      const raw = JSON.parse(fs.readFileSync(this.paths.config,'utf8'));
      const normalized = this._normalizeConfig(raw);
      this._configCache = normalized;
      return JSON.parse(JSON.stringify(normalized));
    } catch {
      const normalized = this._normalizeConfig(null);
      this._configCache = normalized;
      atomicWrite(this.paths.config, JSON.stringify(normalized, null, 2));
      return JSON.parse(JSON.stringify(normalized));
    }
  }

  _saveConfig(next){
    const normalized = this._normalizeConfig({ ...this._loadConfig(), ...next });
    this._configCache = normalized;
    this._ensureLayout();
    atomicWrite(this.paths.config, JSON.stringify(normalized, null, 2));
    return normalized;
  }

  _ensureLayout(){
    ensureDir(this.baseDir);
    ensureDir(this.caDir);
    ensureDir(this.usersDir);
    ensureDir(this.crlDir);
    ensureDir(this.ocspDir);
  }

  _defaultSubjectFor(record, emailOriginal){
    const base = Object.assign({}, this.subjectDefaults || {});
    const fullName = [record.name, record.surname].filter(Boolean).join(' ').trim();
    if (!base.CN) {
      base.CN = fullName || emailOriginal || `user-${record.id}`;
    }
    if (emailOriginal && !base.emailAddress) {
      base.emailAddress = emailOriginal;
    }
    return pruneObject(base);
  }

  _issuerDER(caCertPem){
    if(this._issuerDerCache){
      return Buffer.from(this._issuerDerCache);
    }
    const cfg = this._loadConfig();
    if(cfg.subjectJson){
      const der = subjectFromJSON(cfg.subjectJson);
      this._issuerDerCache = der;
      return Buffer.from(der);
    }
    if(caCertPem){
      const caDer = fromPEM(caCertPem,'CERTIFICATE');
      const tbs = parseCertTbs(caDer);
      const issuer = issuerNameDER(caDer, tbs);
      this._issuerDerCache = Buffer.from(issuer);
      return Buffer.from(issuer);
    }
    throw new Error('Issuer bilgisi yüklenemedi');
  }

  _signerKind(privPem){
    const key = crypto.createPrivateKey(privPem);
    const type = key.asymmetricKeyType;
    if(type === 'ec') return 'EC';
    if(type === 'rsa') return 'RSA';
    throw new Error('Desteklenmeyen imzalama anahtarı');
  }

  _kuFromSpki(spkiDer){
    const top = readTLV(spkiDer,0);
    const alg = readTLV(spkiDer, top.start);
    const algSeq = readTLV(spkiDer, alg.start);
    const oid = readTLV(spkiDer, algSeq.start);
    const name = oidToString(spkiDer.slice(oid.start, oid.end));
    if(name === O.alg.id_ecPublicKey){
      return extKeyUsage({ digitalSignature:true, keyAgreement:true, critical:true });
    }
    if(name === O.alg.rsaEncryption){
      return extKeyUsage({ digitalSignature:true, keyEncipherment:true, critical:true });
    }
    return extKeyUsage({ digitalSignature:true, critical:true });
  }

  _sanityCheckCertWithCA(certPem, caCertPem){
    if(!isCertPEM(certPem)) throw new Error('Geçersiz sertifika PEM');
    if(!isCertPEM(caCertPem)) throw new Error('Geçersiz CA sertifikası');
    const leaf = new X509Certificate(certPem);
    const ca = new X509Certificate(caCertPem);
    if(!leaf.verify(ca.publicKey)){
      throw new Error('Sertifika imzası CA anahtarı ile doğrulanamadı');
    }
    return true;
  }

  _allocateSerial(usedSet=null, byteLength=16){
    const used = new Set();
    if(usedSet && typeof usedSet.forEach === 'function'){
      usedSet.forEach(value => {
        const hex = sanitizeHexString(value);
        if(hex) used.add(hex);
      });
    }

    const size = Math.min(32, Math.max(8, Math.trunc(byteLength || 16)));
    const maxAttempts = 1024;
    for(let attempt=0; attempt<maxAttempts; attempt++){
      let buf = randPos(size);
      if(!buf.some(b => b !== 0x00)) continue;
      if(buf[0] & 0x80){
        buf = Buffer.concat([Buffer.from([0x00]), buf]);
      }
      const hex = sanitizeHexString(bufToHex(buf));
      if(!hex) continue;
      if(used.has(hex)) continue;
      used.add(hex);
      return { buf, hex };
    }
    throw new Error('Yeni benzersiz seri numarası üretilemedi');
  }

  _usersFile(){
    return this.usersFilePath ? path.resolve(this.usersFilePath) : path.resolve(this.baseDir, '..', 'users.json');
  }

  _loadUsersData(){
    const file = this._usersFile();
    let raw = null;
    try { raw = fs.readFileSync(file, 'utf8'); } catch { raw = null; }
    let arr = [];
    if(raw){
      try { arr = JSON.parse(raw); }
      catch { throw new Error('users.json geçerli JSON değil'); }
    }
    if(!Array.isArray(arr)) throw new Error('users.json must be an array');
    const byId = new Map();
    const byEmail = new Map();
    arr.forEach((user, index) => {
      if(!user || typeof user !== 'object') return;
      if(user.id){
        const id = String(user.id);
        if(!byId.has(id)) byId.set(id, index);
      }
      if(user.email){
        const email = String(user.email).trim().toLowerCase();
        if(email && !byEmail.has(email)) byEmail.set(email, index);
      }
      this._ensureUserShape(user);
    });
    return { file, users: arr, byId, byEmail };
  }

  _saveUsersData(data){
    const payload = JSON.stringify(data.users, null, 2) + '\n';
    atomicWrite(data.file, payload);
    return data;
  }

  _ensureUserShape(user){
    if(!user || typeof user !== 'object') return;

    if(!Array.isArray(user.revocations)){
      const legacy = Array.isArray(user.revokedCertificates) ? user.revokedCertificates : [];
      user.revocations = legacy;
      delete user.revokedCertificates;
    }

    if(user.certificate && typeof user.certificate !== 'object'){
      user.certificate = null;
    }

    if(user.certificate){
      const cert = user.certificate;
      const serial = cert.serial ? sanitizeHexString(cert.serial) : null;
      const normalized = pruneObject({
        serial,
        issuedAt: cert.issuedAt || null,
        notAfter: cert.notAfter || null,
        revokedAt: cert.revokedAt || null,
        revocationReason: cert.revocationReason || null,
        certPath: cert.certPath || null,
        csrPath: cert.csrPath || null,
        keyPath: cert.keyPath || null,
        publicKeyPath: cert.publicKeyPath || null,
        ecPrivateKeyFormat: cert.ecPrivateKeyFormat || null,
        san: Array.isArray(cert.san) ? cert.san.filter(Boolean) : null
      });
      user.certificate = Object.keys(normalized).length ? normalized : null;
    }

    user.revocations = user.revocations
      .map(item => {
        if(!item || typeof item !== 'object') return null;
        const serial = item.serial ? sanitizeHexString(item.serial) : null;
        if(!serial) return null;
        const revokedAt = item.revokedAt ? new Date(item.revokedAt) : null;
        const revokedAtIso = revokedAt && !Number.isNaN(revokedAt.valueOf()) ? revokedAt.toISOString() : null;
        const reason = item.reason || null;
        return pruneObject({
          serial,
          revokedAt: revokedAtIso,
          reason
        });
      })
      .filter(item => item && Object.keys(item).length);
  }

  _collectUsedSerials(users){
    const set = new Set();
    (users || []).forEach(user => {
      if(!user || typeof user !== 'object') return;
      if(user.certificate && user.certificate.serial){
        const hex = sanitizeHexString(user.certificate.serial);
        if(hex) set.add(hex);
      }
      if(Array.isArray(user.revocations)){
        for(const entry of user.revocations){
          const hex = sanitizeHexString(entry && entry.serial);
          if(hex) set.add(hex);
        }
      }
    });
    return set;
  }

  _collectRevocationEntries(users){
    const map = new Map();
    (users || []).forEach(user => {
      if(!user || typeof user !== 'object') return;
      const email = user.email ? String(user.email).trim().toLowerCase() : null;
      const userId = user.id || null;
      if(user.certificate && user.certificate.serial && user.certificate.revokedAt){
        const serialHex = sanitizeHexString(user.certificate.serial);
        if(serialHex){
          const reason = user.certificate.revocationReason || 'unspecified';
          map.set(serialHex, {
            serialHex,
            userId,
            email,
            revokedAt: user.certificate.revokedAt || new Date().toISOString(),
            reason,
            reasonCode: CRL_REASON_MAP.hasOwnProperty(reason) ? CRL_REASON_MAP[reason] : CRL_REASON_MAP.unspecified
          });
        }
      }
      if(Array.isArray(user.revocations)){
        for(const entry of user.revocations){
          if(!entry) continue;
          const serialHex = sanitizeHexString(entry.serial);
          if(!serialHex) continue;
          const reason = entry.reason || 'unspecified';
          map.set(serialHex, {
            serialHex,
            userId,
            email,
            revokedAt: entry.revokedAt || new Date().toISOString(),
            reason,
            reasonCode: CRL_REASON_MAP.hasOwnProperty(reason) ? CRL_REASON_MAP[reason] : CRL_REASON_MAP.unspecified
          });
        }
      }
    });
    return Array.from(map.values());
  }

  _ocspError(status){
    const code = OCSP_RESPONSE_STATUS.hasOwnProperty(status) ? OCSP_RESPONSE_STATUS[status] : OCSP_RESPONSE_STATUS.internalError;
    return SEQ(wrap(0x0a, Buffer.from([code])), wrap(0xa0, Buffer.alloc(0)));
  }
}

module.exports = { CertificateAuthoritySystem };
