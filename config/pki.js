'use strict';

const defaultRootSubject = {
  C: 'TR',
  ST: 'Sivas',
  L: 'Merkez',
  O: 'Fitfak',
  OU: 'Fitfak Root CA',
  CN: 'Fitfak Root Certificate Authority'
};

const defaultUserSubject = {};

const services = {
  ocspUrl: process.env.PKI_OCSP_URL || 'https://fitfak.net/ocsp',
  crlUrl: process.env.PKI_CRL_URL || 'https://fitfak.net/crl',
  caIssuersUrl: process.env.PKI_CA_ISSUERS_URL || 'https://fitfak.net/aia/ca.crt'
};

module.exports = {
  enabled: process.env.PKI_ENABLED !== 'false',
  baseDir: process.env.PKI_BASE_DIR || null,
  rootSubject: Object.assign({}, defaultRootSubject, (() => {
    if (!process.env.PKI_ROOT_SUBJECT) return {};
    try {
      const parsed = JSON.parse(process.env.PKI_ROOT_SUBJECT);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (err) {
      console.warn('Failed to parse PKI_ROOT_SUBJECT env, using defaults.');
      return {};
    }
  })()),
  rootValidityDays: Number(process.env.PKI_ROOT_VALIDITY_DAYS) || 900,
  rootEcPrivateKeyFormat: process.env.PKI_ROOT_EC_KEY_FORMAT === 'sec1' ? 'sec1' : 'pkcs8',
  subjectDefaults: Object.assign({}, defaultUserSubject, (() => {
    if (!process.env.PKI_USER_SUBJECT_DEFAULTS) return {};
    try {
      const parsed = JSON.parse(process.env.PKI_USER_SUBJECT_DEFAULTS);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (err) {
      console.warn('Failed to parse PKI_USER_SUBJECT_DEFAULTS env, using defaults.');
      return {};
    }
  })()),
  leafValidityDays: Number(process.env.PKI_LEAF_VALIDITY_DAYS) || 180,
  leafEcPrivateKeyFormat: process.env.PKI_LEAF_EC_KEY_FORMAT === 'sec1' ? 'sec1' : 'pkcs8',
  autoRenewThresholdDays: Number.isFinite(Number(process.env.PKI_AUTO_RENEW_THRESHOLD_DAYS))
    ? Number(process.env.PKI_AUTO_RENEW_THRESHOLD_DAYS)
    : 30,
  leafExtendedKeyUsages: (() => {
    if (!process.env.PKI_LEAF_EKU) return ['clientAuth', 'emailProtection'];
    try {
      const parsed = JSON.parse(process.env.PKI_LEAF_EKU);
      if (Array.isArray(parsed)) return parsed;
    } catch (err) {
      console.warn('Failed to parse PKI_LEAF_EKU env, using defaults.');
    }
    return ['clientAuth', 'emailProtection'];
  })(),
  services,
  ocspNextUpdateSeconds: Number(process.env.PKI_OCSP_NEXT_UPDATE_SECONDS) || 12 * 3600,
  crlNextUpdateSeconds: Number(process.env.PKI_CRL_NEXT_UPDATE_SECONDS) || 7 * 24 * 3600
};
