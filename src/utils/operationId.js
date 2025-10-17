'use strict';

const { normalizePermissionMask } = require('./permissions');
const { SnowflakeIdFactory } = require('./snowflake');

class OperationIdFactory {
  constructor({ epoch = Date.UTC(2023, 0, 1) } = {}) {
    this.snowflake = new SnowflakeIdFactory({ epoch });
  }

  generate(permissionMask = 0, nonceOverride = null) {
    const mask = normalizePermissionMask(permissionMask);
    return this.snowflake.generate({ operationCode: mask, nonce: nonceOverride });
  }

  decode(id) {
    const decoded = this.snowflake.decode(id);
    return {
      timestamp: decoded.timestamp,
      permissionMask: decoded.operationCode,
      nonce: decoded.nonce,
    };
  }
}

module.exports = { OperationIdFactory };
