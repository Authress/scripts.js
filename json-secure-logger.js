const stringify = require('json-stringify-safe');
const shortUuid = require('short-uuid');

// Remove unnecessary strings from logging
function replacer(key, value) {
  if (key === 'body' && typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch (error) {
      return value;
    }
  }
  if (value && typeof value === 'string' && key && (key.match(/authorization(?!result)/i) || value.match(/^bearer/i))
    && !value.match(/(eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,})\.[a-zA-Z0-9_-]*/gi)) {
    return '{AUTHORIZATION}';
  }

  if (key && key.match(/(secret|signature)/i) && value) {
    return '{SECRET}';
  }

  if (key && key.match('identity') && value && typeof value === 'object' && Object.prototype.hasOwnProperty.call(value, 'cognitoIdentityPoolId')) {
    return '{-}';
  }

  if (key === 'headers' && value && typeof value === 'object') {
    const uselessHeaders = {
      'accept-language': true,
      'content-length': true,
      'content-type': true,
      'x-forwarded-for': true,
      'x-forwarded-port': true,
      'x-forwarded-proto': true,
      'accept': true,
      'accept-encoding': true
    };
    const newHeaders = Object.keys(value).filter(h => !uselessHeaders[h.toLowerCase()]).reduce((acc, h) => { acc[h] = value[h]; return acc; }, {});
    return JSON.parse(stringify(newHeaders, replacer));
  }

  if (key === 'multiValueHeaders') {
    return undefined;
  }
  if (typeof value === 'string' && value.startsWith('<!DOCTYPE html>')) {
    return '<HTML DOCUMENT></HTML>';
  }
  return value;
}

class RequestLogger {
  constructor(loggerFunc) {
    this.loggerFunc = loggerFunc || console.log;
    this.invocationId = null;
    this.logDebug = true;
    this.startTime = null;
    this.metadata = { tracking: [] };
  }

  startInvocation(metadata) {
    this.invocationId = shortUuid.generate();
    this.startTime = new Date();
    this.metadata = Object.assign({ tracking: [{ Start: this.startTime.toISOString() }] }, metadata || {});
  }

  trackPoint(pointName) {
    this.metadata.tracking.push({ [pointName]: new Date() - this.startTime });
  }

  log(message) {
    let type = typeof message;
    let messageAsObject = message;
    if (type === 'undefined' || (type === 'string' && message === '')) {
      console.error('Empty message string.');
      return;
    } else if (type === 'string') {
      messageAsObject = {
        title: message
      };
    } else if (type === 'object' && Object.keys(message).length === 0) {
      console.error('Empty message object.');
      return;
    }

    if (!messageAsObject.level) {
      messageAsObject.level = 'INFO';
    }

    if (messageAsObject.level === 'DEBUG' && !this.logDebug) {
      return;
    }

    messageAsObject.invocationId = this.invocationId;
    const payload = {
      message: messageAsObject,
      metadata: Object.assign({ nodejs: process.version }, this.metadata)
    };

    let truncateToken = innerPayload => {
      return innerPayload.replace(/(eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,})\.[a-zA-Z0-9_-]*/gi, (m, p1) => `${p1}.<sig>`);
    };

    let stringifiedPayload = truncateToken(stringify(payload, replacer, 2));
    // https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html 256KB => 131072 2-byte characters
    if (stringifiedPayload.length >= 131072) {
      const replacementPayload = {
        invocationId: this.invocationId,
        message: {
          title: 'Payload too large',
          level: 'ERROR',
          originalInfo: {
            level: messageAsObject.level,
            title: messageAsObject.title,
            fields: Object.keys(messageAsObject)
          },
          truncatedPayload: truncateToken(stringify(payload, replacer)).substring(0, 40000)
        }
      };
      stringifiedPayload = stringify(replacementPayload, replacer, 2);
    }
    this.loggerFunc(stringifiedPayload);
  }
}

module.exports = new RequestLogger();
