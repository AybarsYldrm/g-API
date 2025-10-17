'use strict';

const tls = require('tls');
const os = require('os');
const crypto = require('crypto');

class SMTPService {
  constructor(options = {}) {
    this.host = options.host || 'smtp.gmail.com';
    this.port = options.port || 465;
    this.username = options.username || '';
    this.password = options.password || '';
    this.secure = options.secure !== false;
    this.rejectUnauthorized = options.rejectUnauthorized !== false;
    this.clientName = options.clientName || os.hostname();
    this.timeoutMs = options.timeoutMs || 15_000;
    this.defaultFrom = options.defaultFrom || this.username;
  }

  async sendMail({ from, to, cc = [], bcc = [], subject = '', html = '', text = '', attachments = [], headers = {}, messageId = null } = {}) {
    if (!to || (Array.isArray(to) && !to.length)) {
      throw new Error('SMTPService requires at least one recipient');
    }

    const recipients = this.#normalizeAddresses([to, cc, bcc]);
    if (!recipients.length) throw new Error('No recipients resolved');

    const envelopeFrom = from || this.defaultFrom;
    if (!envelopeFrom) throw new Error('Sender address required');

    const mime = this.#composeMime({ from: envelopeFrom, to, cc, subject, html, text, attachments, headers, messageId });

    return new Promise((resolve, reject) => {
      let settled = false;
      const socket = tls.connect({
        host: this.host,
        port: this.port,
        secure: this.secure,
        rejectUnauthorized: this.rejectUnauthorized
      });

      const abort = (err) => {
        if (settled) return;
        settled = true;
        try { socket.end(); } catch (e) {}
        reject(err);
      };

      const finalize = () => {
        if (settled) return;
        settled = true;
        try { socket.end(); } catch (e) {}
        resolve(true);
      };

      const timer = setTimeout(() => abort(new Error('SMTP connection timeout')), this.timeoutMs);

      let buffer = '';
      let step = 'greeting';
      let rcptIndex = 0;
      const commands = [];

      const write = (line) => {
        if (socket.destroyed) return;
        socket.write(line);
      };

      const sendEhlo = () => {
        commands.push(`EHLO ${this.clientName}\r\n`);
      };

      const sendAuth = () => {
        if (!this.username || !this.password) return;
        commands.push('AUTH LOGIN\r\n');
        commands.push(`${Buffer.from(this.username, 'utf8').toString('base64')}\r\n`);
        commands.push(`${Buffer.from(this.password, 'utf8').toString('base64')}\r\n`);
      };

      const sendEnvelope = () => {
        commands.push(`MAIL FROM:<${envelopeFrom}>\r\n`);
        for (const addr of recipients) {
          commands.push(`RCPT TO:<${addr}>\r\n`);
        }
        commands.push('DATA\r\n');
        commands.push(`${mime}\r\n.\r\n`);
        commands.push('QUIT\r\n');
      };

      const flushNext = () => {
        if (!commands.length) return;
        const next = commands.shift();
        write(next);
      };

      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        const lines = buffer.split(/\r?\n/);
        buffer = lines.pop();
        for (const line of lines) {
          if (!line) continue;
          const code = parseInt(line.slice(0, 3), 10);
          const cont = line[3] === '-';
          if (Number.isNaN(code)) continue;
          if (cont) continue;

          switch (step) {
            case 'greeting':
              if (code === 220) {
                sendEhlo();
                step = 'ehlo';
                flushNext();
              } else {
                abort(new Error(`Unexpected SMTP greeting: ${line}`));
              }
              break;
            case 'ehlo':
              if (code === 250) {
                if (commands.length === 0) {
                  sendAuth();
                  sendEnvelope();
                }
                flushNext();
                step = this.username && this.password ? 'authUsername' : 'mailFrom';
              } else {
                abort(new Error(`EHLO rejected: ${line}`));
              }
              break;
            case 'authUsername':
              if (code === 334) {
                flushNext();
                step = 'authPassword';
              } else {
                abort(new Error(`AUTH LOGIN rejected (username): ${line}`));
              }
              break;
            case 'authPassword':
              if (code === 334) {
                flushNext();
                step = 'authFinalize';
              } else {
                abort(new Error(`AUTH LOGIN rejected (password prompt): ${line}`));
              }
              break;
            case 'authFinalize':
              if (code === 235) {
                flushNext();
                step = 'mailFrom';
              } else {
                abort(new Error(`AUTH LOGIN failed: ${line}`));
              }
              break;
            case 'mailFrom':
              if (code === 250) {
                rcptIndex = 0;
                flushNext();
                step = recipients.length ? 'rcpt' : 'data';
              } else {
                abort(new Error(`MAIL FROM rejected: ${line}`));
              }
              break;
            case 'rcpt':
              if (code === 250 || code === 251) {
                rcptIndex++;
                if (rcptIndex < recipients.length) {
                  flushNext();
                } else {
                  flushNext();
                  step = 'data';
                }
              } else {
                abort(new Error(`RCPT TO rejected: ${line}`));
              }
              break;
            case 'data':
              if (code === 354) {
                flushNext();
                step = 'message';
              } else {
                abort(new Error(`DATA rejected: ${line}`));
              }
              break;
            case 'message':
              if (code === 250) {
                flushNext();
                step = 'quit';
              } else {
                abort(new Error(`Message rejected: ${line}`));
              }
              break;
            case 'quit':
              if (code === 221) {
                clearTimeout(timer);
                finalize();
              }
              break;
            default:
              break;
          }
        }
      });

      socket.on('error', (err) => {
        clearTimeout(timer);
        abort(err);
      });

      socket.on('close', () => {
        clearTimeout(timer);
        if (!settled) abort(new Error('SMTP connection closed unexpectedly'));
      });
    });
  }

  #normalizeAddresses(groups) {
    const out = [];
    const push = (value) => {
      if (!value) return;
      if (Array.isArray(value)) {
        value.forEach(push);
      } else if (typeof value === 'string') {
        const trimmed = value.trim();
        if (trimmed) out.push(trimmed);
      }
    };
    groups.forEach(push);
    return out;
  }

  #composeMime({ from, to, cc, subject, html, text, attachments, headers, messageId }) {
    const boundaryMixed = `----=_NodeMailer_${crypto.randomBytes(8).toString('hex')}`;
    const boundaryAlt = `----=_NodeMailerAlt_${crypto.randomBytes(8).toString('hex')}`;
    const lines = [];

    lines.push(`From: ${from}`);
    lines.push(this.#formatAddressLine('To', to));
    const ccLine = this.#formatAddressLine('Cc', cc);
    if (ccLine) lines.push(ccLine);
    if (messageId) lines.push(`Message-ID: <${messageId}>`);
    lines.push(`Subject: ${this.#encodeHeader(subject)}`);
    lines.push('MIME-Version: 1.0');
    lines.push('X-Mailer: GraphAPI SMTPService');

    Object.entries(headers || {}).forEach(([key, value]) => {
      if (!key) return;
      lines.push(`${key}: ${value}`);
    });

    const hasAttachments = Array.isArray(attachments) && attachments.length > 0;
    const hasText = Boolean(text);
    const hasHtml = Boolean(html);

    if (hasAttachments) {
      lines.push(`Content-Type: multipart/mixed; boundary="${boundaryMixed}"`);
      lines.push('');
      lines.push(`--${boundaryMixed}`);
      lines.push(`Content-Type: multipart/alternative; boundary="${boundaryAlt}"`);
      lines.push('');
      this.#appendAlternative(lines, boundaryAlt, text, html);
      for (const attachment of attachments) {
        this.#appendAttachment(lines, boundaryMixed, attachment);
      }
      lines.push(`--${boundaryMixed}--`);
    } else if (hasText && hasHtml) {
      lines.push(`Content-Type: multipart/alternative; boundary="${boundaryAlt}"`);
      lines.push('');
      this.#appendAlternative(lines, boundaryAlt, text, html);
    } else {
      const body = hasHtml ? html : (text || '');
      const contentType = hasHtml ? 'text/html' : 'text/plain';
      lines.push(`Content-Type: ${contentType}; charset=utf-8`);
      lines.push('Content-Transfer-Encoding: 7bit');
      lines.push('');
      lines.push(body);
    }

    return lines.join('\r\n');
  }

  #formatAddressLine(label, value) {
    const addresses = this.#normalizeAddresses([value]);
    if (!addresses.length) return null;
    return `${label}: ${addresses.join(', ')}`;
  }

  #appendAlternative(lines, boundary, text, html, nested = true) {
    if (nested) {
      lines.push(`--${boundary}`);
    }
    if (text) {
      lines.push(`Content-Type: text/plain; charset=utf-8`);
      lines.push('Content-Transfer-Encoding: 7bit');
      lines.push('');
      lines.push(text);
      lines.push('');
      if (nested) lines.push(`--${boundary}`);
    }
    const htmlToSend = html || (!text ? '<p></p>' : null);
    if (htmlToSend) {
      lines.push(`Content-Type: text/html; charset=utf-8`);
      lines.push('Content-Transfer-Encoding: 7bit');
      lines.push('');
      lines.push(htmlToSend);
      lines.push('');
    }
    if (nested) {
      lines.push(`--${boundary}--`);
      lines.push('');
    }
  }

  #appendAttachment(lines, boundary, attachment) {
    if (!attachment) return;
    const filename = attachment.filename || `file-${Date.now()}`;
    const contentType = attachment.contentType || 'application/octet-stream';
    const content = attachment.content;
    const buffer = Buffer.isBuffer(content)
      ? content
      : typeof content === 'string'
        ? Buffer.from(content, attachment.encoding || 'utf8')
        : Buffer.from(String(content || ''), 'utf8');
    const encoded = buffer.toString('base64');
    const chunks = encoded.match(/.{1,76}/g) || [];

    lines.push(`--${boundary}`);
    lines.push(`Content-Type: ${contentType}; name="${filename}"`);
    lines.push('Content-Transfer-Encoding: base64');
    lines.push(`Content-Disposition: attachment; filename="${filename}"`);
    lines.push('');
    lines.push(chunks.join('\r\n'));
    lines.push('');
  }

  #encodeHeader(value) {
    if (!value) return '';
    if (/^[\x00-\x7F]*$/.test(value)) return value;
    const buffer = Buffer.from(value, 'utf8');
    return `=?UTF-8?B?${buffer.toString('base64')}?=`;
  }
}

module.exports = { SMTPService };
