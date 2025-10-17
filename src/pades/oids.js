'use strict';

const OIDS = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingCertificateV2: '1.2.840.113549.1.9.16.2.47',
  signatureTimeStampToken: '1.2.840.113549.1.9.16.2.14',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  rsaEncryption: '1.2.840.113549.1.1.1',
  sha256WithRSAEncryption: '1.2.840.113549.1.1.11',
  sha384WithRSAEncryption: '1.2.840.113549.1.1.12',
  sha512WithRSAEncryption: '1.2.840.113549.1.1.13',
  ecdsa_with_SHA256: '1.2.840.10045.4.3.2',
  ecdsa_with_SHA384: '1.2.840.10045.4.3.3',
  ecdsa_with_SHA512: '1.2.840.10045.4.3.4',
  idEcPublicKey: '1.2.840.10045.2.1',
  prime256v1: '1.2.840.10045.3.1.7',
  secp384r1: '1.3.132.0.34',
  secp521r1: '1.3.132.0.35',
  id_kp_timeStamping: '1.3.6.1.5.5.7.3.8',
};

const HASH_BY_NAME = {
  sha256: OIDS.sha256,
  sha384: OIDS.sha384,
  sha512: OIDS.sha512,
};

const RSA_SIG_BY_HASH = {
  sha256: OIDS.sha256WithRSAEncryption,
  sha384: OIDS.sha384WithRSAEncryption,
  sha512: OIDS.sha512WithRSAEncryption,
};

const ECDSA_SIG_BY_HASH = {
  sha256: OIDS.ecdsa_with_SHA256,
  sha384: OIDS.ecdsa_with_SHA384,
  sha512: OIDS.ecdsa_with_SHA512,
};

const CURVE_HASH = {
  [OIDS.prime256v1]: 'sha256',
  [OIDS.secp384r1]: 'sha384',
  [OIDS.secp521r1]: 'sha512',
};

function digestOidByName(hashName = 'sha256') {
  const normalized = String(hashName || 'sha256').toLowerCase();
  if (!HASH_BY_NAME[normalized]) {
    throw new Error(`Unsupported hash algorithm: ${hashName}`);
  }
  return HASH_BY_NAME[normalized];
}

function rsaSigOidByHash(hashName = 'sha256') {
  const normalized = String(hashName || 'sha256').toLowerCase();
  if (!RSA_SIG_BY_HASH[normalized]) {
    throw new Error(`Unsupported RSA signature hash: ${hashName}`);
  }
  return RSA_SIG_BY_HASH[normalized];
}

function ecdsaSigOidByHash(hashName = 'sha256') {
  const normalized = String(hashName || 'sha256').toLowerCase();
  if (!ECDSA_SIG_BY_HASH[normalized]) {
    throw new Error(`Unsupported ECDSA signature hash: ${hashName}`);
  }
  return ECDSA_SIG_BY_HASH[normalized];
}

function recommendHashForCurve(curveOid) {
  return CURVE_HASH[curveOid] || 'sha256';
}

module.exports = {
  OIDS,
  digestOidByName,
  rsaSigOidByHash,
  ecdsaSigOidByHash,
  recommendHashForCurve,
};
