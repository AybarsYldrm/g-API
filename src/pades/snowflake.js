const crypto = require("crypto");

class Snowflake {
  /**
   * @param secret HMAC için secure mode
   * @param epoch başlangıç timestamp
   * @param ttlMs secure mode TTL (ms)
   */
  constructor(secret, epoch = 1700000000000n, ttlMs = 60000) {
    this.secret = secret;
    this.epoch = BigInt(epoch);
    this.ttlMs = BigInt(ttlMs);
  }

  // --- Secure Mode Token (64+64 bit HMAC) ---
  createSecure(permissionId, actionId) {
    const timestamp = BigInt(Date.now()) - this.epoch;       // 41 bit
    const random = BigInt(crypto.randomInt(0, 8)) & 0x7n;   // 3 bit
    const action = BigInt(actionId) & 0x3Fn;                // 6 bit
    const permission = BigInt(permissionId) & 0x3FFFn;      // 14 bit

    // 41 + 3 + 6 + 14 = 64 bit Snowflake
    const snowflake = (timestamp << 23n) | (random << 20n) | (action << 14n) | permission;

    // Buffer 8 byte
    const idBuf = Buffer.alloc(8);
    idBuf.writeBigUInt64BE(snowflake);

    // HMAC 64 bit
    const tagBuf = crypto.createHmac("sha256", this.secret)
                         .update(idBuf)
                         .digest()
                         .subarray(0, 8);
    const tag = BigInt("0x" + tagBuf.toString("hex"));

    // 128-bit birleşim → decimal string
    const tokenBig = (snowflake << 64n) | tag;
    return tokenBig.toString(10);
  }

  verifySecure(tokenDec) {
    const tokenBig = BigInt(tokenDec);

    const snowflake = tokenBig >> 64n;
    const tag = tokenBig & ((1n << 64n) - 1n);

    const idBuf = Buffer.alloc(8);
    idBuf.writeBigUInt64BE(snowflake);

    const expectedTagBuf = crypto.createHmac("sha256", this.secret)
                                 .update(idBuf)
                                 .digest()
                                 .subarray(0, 8);
    const expectedTag = BigInt("0x" + expectedTagBuf.toString("hex"));

    if (tag !== expectedTag) return { ok: false, error: "HMAC mismatch" };

    // Decode Snowflake
    const timestamp = (snowflake >> 23n) + this.epoch;
    const random = (snowflake >> 20n) & 0x7n;           // 3 bit
    const actionId = (snowflake >> 14n) & 0x3Fn;        // 6 bit
    const permissionId = snowflake & 0x3FFFn;           // 14 bit

    const now = BigInt(Date.now());
    if (now > timestamp + this.ttlMs) return { ok: false, error: "Expired" };

    return {
      ok: true,
      timestamp: Number(timestamp),
      permissionId: Number(permissionId),
      actionId: Number(actionId),
      random: Number(random)
    };
  }

  // --- Plain Mode (64-bit Snowflake, HMAC yok) ---
  createPlain(permissionId, actionId) {
    const timestamp = BigInt(Date.now()) - this.epoch;
    const random = BigInt(crypto.randomInt(0, 8)) & 0x7n;
    const action = BigInt(actionId) & 0x3Fn;
    const permission = BigInt(permissionId) & 0x3FFFn;

    const snowflake = (timestamp << 23n) | (random << 20n) | (action << 14n) | permission;
    return snowflake.toString(10);
  }

  verifyPlain(snowflakeDec) {
    const snowflake = BigInt(snowflakeDec);
    const timestamp = (snowflake >> 23n) + this.epoch;
    const random = (snowflake >> 20n) & 0x7n;
    const actionId = (snowflake >> 14n) & 0x3Fn;
    const permissionId = snowflake & 0x3FFFn;

    return {
      timestamp: Number(timestamp),
      permissionId: Number(permissionId),
      actionId: Number(actionId),
      random: Number(random)
    };
  }
}

module.exports = { Snowflake };