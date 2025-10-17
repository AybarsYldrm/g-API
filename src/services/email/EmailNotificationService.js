'use strict';

const crypto = require('crypto');

class EmailNotificationService {
  constructor({ smtpService, defaultFrom, appBaseUrl = '' } = {}) {
    if (!smtpService) throw new Error('EmailNotificationService requires smtpService');
    this.smtp = smtpService;
    this.defaultFrom = defaultFrom || this.smtp.defaultFrom;
    this.appBaseUrl = appBaseUrl.replace(/\/?$/, '');
  }

  async sendWelcome(user, { isNew = true } = {}) {
    if (!user || !user.email) return;
    const subject = isNew
      ? 'Aramıza hoş geldiniz'
      : 'Tekrar hoş geldiniz';
    const dashboardUrl = this.appBaseUrl ? `${this.appBaseUrl}/dashboard` : '/dashboard';

    const html = `
      <div style="font-family: Arial, sans-serif; color: #1f2933;">
        <h2>Merhaba ${this.#escape(user.name || user.email)},</h2>
        <p>Microsoft hesabınız ile sisteme ${isNew ? 'ilk kez' : 'yeniden'} giriş yaptığınızı gördük.</p>
        <p>Başlamak için <a href="${dashboardUrl}">kontrol panelini</a> ziyaret edebilirsiniz.</p>
        <p>Eğer bu işlemi siz yapmadıysanız lütfen güvenlik ekibimizle iletişime geçin.</p>
      </div>
    `;

    const text = [
      `Merhaba ${user.name || user.email},`,
      `Microsoft hesabınız ile sisteme ${isNew ? 'ilk kez' : 'yeniden'} giriş yaptığınızı gördük.`,
      `Başlamak için ${dashboardUrl} adresini ziyaret edebilirsiniz.`,
      'Eğer bu işlemi siz yapmadıysanız lütfen güvenlik ekibimizle iletişime geçin.'
    ].join('\n');

    const messageId = `${crypto.randomBytes(16).toString('hex')}@graph-api.local`;

    await this.smtp.sendMail({
      from: this.defaultFrom,
      to: user.email,
      subject,
      html,
      text,
      messageId
    });
  }

  #escape(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}

module.exports = { EmailNotificationService };
