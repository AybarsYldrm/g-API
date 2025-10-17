'use strict';
const fs = require('fs');
const path = require('path');
const { PAdESManager } = require('./pades_manager');
const { Snowflake } = require('./snowflake');

(async () => {
  const baseDir = __dirname;
  const TSA_URL = process.env.TSA_URL || 'http://timestamp.digicert.com';
  const INPUT = path.join(baseDir, 'certificate.pdf');
  const OUT_PADES_T = path.join(baseDir, 'output_pades_T.pdf');
  const OUT_PADES_T_WITH_DOC_TS = path.join(baseDir, 'output_pades_T_with_docTS.pdf');
  const OUT_DOC_TS_ONLY = path.join(baseDir, 'output_docTS_only.pdf');
  const KEY_PATH = path.join(baseDir, 'key.pem');
  const CERT_PATH = path.join(baseDir, 'cert.pem');

  const pm = new PAdESManager({
    tsaUrl: TSA_URL,
    tsaOptions: { hashName: 'sha384', certReq: true }
  });

  const snowflake = new Snowflake({})


  const pdfSource = fs.readFileSync(INPUT);
  const keyPem = fs.readFileSync(KEY_PATH, 'utf8');
  const certPem = fs.readFileSync(CERT_PATH, 'utf8');
  const chain = []; // ['issuer.pem','root.pem'].map(p=>fs.readFileSync(path.join(baseDir, p),'utf8'));

  // PAdES-T (tek imzada imza + TSA attribute)
  try {
    const { pdf, mode } = await pm.signPAdES_T({
      pdfBuffer: Buffer.from(pdfSource),
      keyPem,
      certPem,
      chainPems: chain,
      fieldName: snowflake.createPlain(1, 1),
      placeholderHexLen: 120000,
      documentTimestamp: { append: false }
    });
    fs.writeFileSync(OUT_PADES_T, pdf);
    console.log('OK', mode, '→', OUT_PADES_T);
  } catch (e) {
    console.error('PAdES-T error:', e.code || e.message || e);
  }

  // PAdES-T + DocTimeStamp (dijital imza + belge zaman damgası)
  try {
    const { pdf, mode } = await pm.signPAdES_T({
      pdfBuffer: Buffer.from(pdfSource),
      keyPem,
      certPem,
      chainPems: chain,
      fieldName: null,
      placeholderHexLen: 120000,
      documentTimestamp: {
        append: true,
        fieldName: 'DocTS',
        placeholderHexLen: 64000
      }
    });
    fs.writeFileSync(OUT_PADES_T_WITH_DOC_TS, pdf);
    console.log('OK', mode, '→', OUT_PADES_T_WITH_DOC_TS);
  } catch (e) {
    console.error('PAdES-T+DocTS error:', e.code || e.message || e);
  }

  // DocTimeStamp (belge zaman damgası tek başına)
  try {
    const out = await pm.addDocTimeStamp({
      pdfBuffer: Buffer.from(pdfSource),
      fieldName: null,
      placeholderHexLen: 64000
    });
    fs.writeFileSync(OUT_DOC_TS_ONLY, out);
    console.log('OK docts →', OUT_DOC_TS_ONLY);
  } catch (e) {
    console.error('DocTS error:', e.code || e.message || e);
  }
})();
