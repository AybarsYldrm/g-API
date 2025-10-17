'use strict';

const DEFAULT_TIMESTAMP_BITS = 42n;
const DEFAULT_OPERATION_BITS = 18n;
const DEFAULT_NONCE_BITS = 4n;

class SnowflakeIdFactory {
  constructor({ epoch = Date.UTC(2023, 0, 1), timestampBits = DEFAULT_TIMESTAMP_BITS, operationBits = DEFAULT_OPERATION_BITS, nonceBits = DEFAULT_NONCE_BITS } = {}) {
    this.epoch = BigInt(epoch);
    this.timestampBits = BigInt(timestampBits);
    this.operationBits = BigInt(operationBits);
    this.nonceBits = BigInt(nonceBits);

    this.maxTimestamp = (1n << this.timestampBits) - 1n;
    this.operationMask = (1n << this.operationBits) - 1n;
    this.nonceMask = (1n << this.nonceBits) - 1n;

    this.lastTimestamp = 0n;
    this.sequence = 0n;
  }

  _timestamp() {
    const now = BigInt(Date.now());
    const relative = now - this.epoch;
    return relative < 0n ? 0n : relative;
  }

  generate(operationCodeOrOptions = 0, maybeNonce = null) {
    let operationCode;
    let nonceOverride = maybeNonce;

    if (operationCodeOrOptions && typeof operationCodeOrOptions === 'object' && !Array.isArray(operationCodeOrOptions)) {
      operationCode = operationCodeOrOptions.operationCode || 0;
      nonceOverride = operationCodeOrOptions.nonce ?? null;
    } else {
      operationCode = operationCodeOrOptions;
    }

    let timestamp = this._timestamp();
    if (timestamp > this.maxTimestamp) {
      throw new Error('Snowflake timestamp overflow');
    }

    if (timestamp < this.lastTimestamp) {
      timestamp = this.lastTimestamp;
    }

    let sequence;
    if (nonceOverride === null || nonceOverride === undefined) {
      if (timestamp === this.lastTimestamp) {
        this.sequence = (this.sequence + 1n) & this.nonceMask;
        if (this.sequence === 0n) {
          do {
            timestamp = this._timestamp();
          } while (timestamp <= this.lastTimestamp);
        }
      } else {
        this.sequence = 0n;
      }
      sequence = this.sequence;
    } else {
      const forced = BigInt(Number(nonceOverride) & Number(this.nonceMask));
      sequence = forced & this.nonceMask;
    }

    this.lastTimestamp = timestamp;

    const opCode = BigInt(Number(operationCode) & Number(this.operationMask));
    const id = (timestamp << (this.operationBits + this.nonceBits))
      | (opCode << this.nonceBits)
      | sequence;
    return id.toString();
  }

  decode(id) {
    const big = BigInt(id);
    const sequence = Number(big & this.nonceMask);
    const operationCode = Number((big >> this.nonceBits) & this.operationMask);
    const timestampPart = Number(big >> (this.operationBits + this.nonceBits));
    const absolute = Number(this.epoch) + timestampPart;
    return {
      timestamp: new Date(absolute).toISOString(),
      operationCode,
      nonce: sequence
    };
  }
}

module.exports = { SnowflakeIdFactory };
