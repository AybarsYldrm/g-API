'use strict';
const crypto = require('crypto');
const { readLastTrailer, readObject } = require('./pdf_parser');

function inspectPdfSignatures(pdfBuffer) {
  if (!Buffer.isBuffer(pdfBuffer)) {
    throw new Error('pdfBuffer must be a Buffer');
  }

  const { size } = readLastTrailer(pdfBuffer);
  const pdfLen = pdfBuffer.length;
  const signatures = [];
  let byteRangeCount = 0;
  let hasIssues = false;

  for (let objNum = 0; objNum < size + 5; objNum++) {
    const obj = readObject(pdfBuffer, objNum);
    if (!obj || !obj.dictStr) continue;
    const typeMatch = /\/Type\s*\/([A-Za-z0-9]+)/.exec(obj.dictStr);
    const rawType = typeMatch ? typeMatch[1] : null;
    const subFilterMatch = /\/SubFilter\s*\/([A-Za-z0-9\.\-]+)/.exec(obj.dictStr);
    const subFilter = subFilterMatch ? subFilterMatch[1] : null;

    let resolvedType = null;
    if (subFilter === 'ETSI.RFC3161') {
      resolvedType = 'DocTimeStamp';
    } else if (rawType === 'DocTimeStamp') {
      resolvedType = 'DocTimeStamp';
    } else if (rawType === 'Sig') {
      resolvedType = 'Sig';
    }

    if (!resolvedType) continue;

    const entry = {
      objNum,
      type: resolvedType,
      rawType,
      subFilter: null,
      byteRange: null,
      byteRangeSegments: [],
      contents: null,
      coveredSha256: null,
      issues: []
    };

    if (subFilterMatch) {
      entry.subFilter = subFilterMatch[1];
    }

    const byteRangeMatch = /\/ByteRange\s*\[([^\]]+)\]/.exec(obj.dictStr);
    if (byteRangeMatch) {
      const parts = byteRangeMatch[1]
        .trim()
        .split(/\s+/)
        .map((v) => {
          const parsed = parseInt(v, 10);
          return Number.isFinite(parsed) ? parsed : NaN;
        })
        .filter((v) => !Number.isNaN(v));

      if (parts.length % 2 !== 0 || parts.length === 0) {
        entry.issues.push('ByteRange must contain an even number of integers.');
      } else {
        entry.byteRange = parts;
        entry.byteRangeSource = byteRangeMatch[0];
        entry.byteRangeSourceSnippet = byteRangeMatch[0].slice(0, 120);
        entry.byteRangeSections = parts.length / 2;
        byteRangeCount++;
        let previousEnd = -1;
        let segmentsValid = true;
        for (let i = 0; i < parts.length; i += 2) {
          const start = parts[i];
          const length = parts[i + 1];
          const end = start + length;
          const segment = { start, length, end };
          entry.byteRangeSegments.push(segment);

          if (start < 0 || length < 0) {
            entry.issues.push('ByteRange segment has negative offset or length.');
            segmentsValid = false;
          }
          if (end > pdfLen) {
            entry.issues.push('ByteRange segment extends beyond the PDF length.');
            segmentsValid = false;
          }
          if (previousEnd > start) {
            entry.issues.push('ByteRange segments overlap or are unsorted.');
            segmentsValid = false;
          }
          previousEnd = end;
        }

        if (segmentsValid) {
          const coveredParts = entry.byteRangeSegments.map((seg) =>
            pdfBuffer.subarray(seg.start, seg.end)
          );
          const covered = Buffer.concat(coveredParts);
          entry.coveredSha256 = crypto
            .createHash('sha256')
            .update(covered)
            .digest('hex');
        }
      }
    } else {
      entry.issues.push('Missing /ByteRange array.');
    }

    const contentsRegex = /\/Contents\s*<([\s\S]*?)>/m;
    const contentsMatch = contentsRegex.exec(obj.dictStr);
    if (contentsMatch) {
      const raw = contentsMatch[1].replace(/\s+/g, '');
      const ltIndex = obj.dictStr.indexOf('<', contentsMatch.index);
      const gtIndex = obj.dictStr.indexOf('>', ltIndex);

      if (ltIndex < 0 || gtIndex < 0) {
        entry.issues.push('Unable to determine /Contents bounds.');
      }

      const absStart =
        typeof obj.start === 'number' && obj.start >= 0 && ltIndex >= 0
          ? obj.start + ltIndex
          : null;
      const absEnd =
        typeof obj.start === 'number' && obj.start >= 0 && gtIndex >= 0
          ? obj.start + gtIndex
          : null;

      entry.contents = {
        hex: raw,
        length: Math.floor(raw.length / 2),
        isLikelyPlaceholder: /^0+$/i.test(raw),
        offsetStart: absStart != null ? absStart + 1 : null,
        offsetEnd: absEnd != null ? absEnd : null
      };

      if (entry.byteRangeSegments.length >= 2 && absStart != null && absEnd != null) {
        const hexStart = absStart + 1;
        const hexEndExclusive = absEnd;
        let gapFound = false;
        for (let i = 0; i < entry.byteRangeSegments.length - 1; i++) {
          const segEnd = entry.byteRangeSegments[i].end;
          const nextStart = entry.byteRangeSegments[i + 1].start;
          if (hexStart >= segEnd && hexEndExclusive <= nextStart) {
            gapFound = true;
            break;
          }
        }
        if (!gapFound) {
          entry.issues.push('CONTENTS_WITHIN_HASH_RANGE');
          entry.issues.push('ByteRange gap does not enclose signature /Contents.');
        }
      }
    } else {
      entry.issues.push('Missing /Contents entry.');
    }

    if (entry.issues.length > 0) {
      hasIssues = true;
    }
    signatures.push(entry);
  }

  return { signatures, byteRangeCount, hasIssues };
}

module.exports = { inspectPdfSignatures };
