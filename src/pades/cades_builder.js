'use strict';
const crypto = require('crypto');
const { DER } = require('./asn1_der');
const { OIDS, digestOidByName, rsaSigOidByHash, ecdsaSigOidByHash } = require('./oids');
const { pemToDer, parseCertBasics } = require('./x509_extract');

function buildSigningCertificateV2(certDer){
  const certHash = crypto.createHash('sha256').update(certDer).digest();
  const { issuerFullDER, serialContent } = parseCertBasics(certDer);
  // IssuerSerial = SEQ { GeneralNames (directoryName=[4] Name), serialNumber INTEGER }
  const directoryName = DER.ctxExplicit(4, DER.any(issuerFullDER));
  const generalNames = DER.seq(directoryName);
  const issuerSerial = DER.seq(generalNames, DER.intFromBuf(serialContent));
  const essCertIdV2 = DER.seq(DER.algo(OIDS.sha256), DER.octet(certHash), issuerSerial);
  const signingCertV2 = DER.seq(essCertIdV2);
  return DER.seq(DER.oid(OIDS.signingCertificateV2), DER.set(signingCertV2));
}
function buildContentTypeAttr(){ return DER.seq(DER.oid(OIDS.contentType), DER.set(DER.oid(OIDS.data))); }
function buildMessageDigestAttr(hashBuf){ return DER.seq(DER.oid(OIDS.messageDigest), DER.set(DER.octet(hashBuf))); }
function buildSignedAttrs(tbsHash, leafCertDer){
  const attrs = [ buildContentTypeAttr(), buildMessageDigestAttr(tbsHash), buildSigningCertificateV2(leafCertDer) ];
  const toSign = DER.set(...attrs);
  const forCms = DER.retagImplicit(toSign, 0xA0); // [0] IMPLICIT
  return { toSign, forCms };
}
function signSignedAttrs(signedAttrs, keyPem, hashName, keyType){
  const toSign = signedAttrs.toSign ?? signedAttrs;
  if (keyType==='rsa'){ const s=crypto.createSign(`RSA-${hashName.toUpperCase()}`); s.update(toSign); return s.sign(keyPem); }
  if (keyType==='ecdsa'){ const s=crypto.createSign(hashName.toUpperCase()); s.update(toSign); return s.sign({ key:keyPem }); }
  throw new Error('keyType must be rsa|ecdsa');
}
function buildSignerInfo_issuerSerial(leafCertDer, signature, signedAttrsForCms, keyType, hashName){
  const { issuerFullDER, serialContent } = parseCertBasics(leafCertDer);
  const sid = DER.seq(DER.any(issuerFullDER), DER.intFromBuf(serialContent));
  const digestAlg = DER.algo(digestOidByName(hashName));
  const sigAlgOid = keyType==='rsa' ? rsaSigOidByHash(hashName) : ecdsaSigOidByHash(hashName);
  const sigAlg = keyType==='rsa' ? DER.algo(sigAlgOid) : DER.algo(sigAlgOid, false);
  return DER.seq(
    DER.intFromBuf(Buffer.from([0x01])),
    sid,
    digestAlg,
    DER.any(signedAttrsForCms),
    sigAlg,
    DER.octet(signature)
  );
}
function addUnsignedAttr_signatureTimeStampToken(signerInfoDer, tsTokenDer){
  const attr = DER.seq(DER.oid(OIDS.signatureTimeStampToken), DER.set(DER.any(tsTokenDer)));
  const unsignedSet = DER.set(attr);
  const unsignedImplicit = DER.retagImplicit(unsignedSet, 0xA1); // [1]
  const tlv = readTLV_local(signerInfoDer, 0);
  if (tlv.tag!==0x30) throw new Error('signerInfo not SEQ');
  const body = signerInfoDer.slice(tlv.start, tlv.end);
  return DER.seq(DER.any(Buffer.concat([body, unsignedImplicit])));
}
function buildSignedData(digestHashName, certsDerArray, signerInfoDer){
  const digestAlgs = DER.set(DER.algo(digestOidByName(digestHashName)));
  const eci = DER.seq(DER.oid(OIDS.data)); // detached
  const certSet = DER.set(...certsDerArray.map(der=>DER.any(der)));
  const certsImplicit = DER.retagImplicit(certSet, 0xA0); // [0]
  const signerInfos = DER.set(signerInfoDer);
  const sd = DER.seq(DER.intFromBuf(Buffer.from([0x01])), digestAlgs, eci, certsImplicit, signerInfos);
  return DER.seq(DER.oid(OIDS.signedData), DER.ctxExplicit(0, sd));
}
function buildCAdES_BES_auto(tbsHash, keyPem, leafCertPem, chainCertPems=[]){
  const leafDer = pemToDer(leafCertPem);
  const { spkiAlgOid, ecCurveOid, recommendedHash } = parseCertBasics(leafDer);
  let keyType, hashName = recommendedHash;
  if (spkiAlgOid === OIDS.idEcPublicKey) keyType = 'ecdsa';
  else if (spkiAlgOid === OIDS.rsaEncryption) { keyType='rsa'; hashName='sha256'; }
  else throw new Error('Unsupported SPKI alg OID: '+spkiAlgOid);

  const need = (hashName==='sha256'?32: hashName==='sha384'?48:64);
  if (tbsHash.length !== need) throw new Error(`tbsHash must be ${hashName} (${need} bytes), got ${tbsHash.length}`);

  const signedAttrs = buildSignedAttrs(tbsHash, leafDer);
  const signature = signSignedAttrs(signedAttrs, keyPem, hashName, keyType);
  const signerInfo = buildSignerInfo_issuerSerial(leafDer, signature, signedAttrs.forCms, keyType, hashName);

  const chainDer = chainCertPems.map(p=>pemToDer(p));
  const cmsBES = buildSignedData(hashName, [leafDer, ...chainDer], signerInfo);

  return { cmsBES, signerInfo, signatureValue: signature, hashName, keyType, leafDer, chainDer, signedAttrs };
}

// tiny local TLV reader
function readTLV_local(buf, pos){
  const t = buf[pos]; let l = buf[pos+1], lenBytes = 1;
  if (l & 0x80) { const n=l&0x7F; l=0; for(let i=0;i<n;i++) l=(l<<8)|buf[pos+2+i]; lenBytes=1+n; }
  const start = pos + 1 + lenBytes, end = start + l;
  return { tag:t, start, end, next:end };
}

module.exports = {
  buildCAdES_BES_auto,
  addUnsignedAttr_signatureTimeStampToken,
  buildSignedData
};
