const jwt = require('jsonwebtoken');
const net = require('net');
const {
  getApiTokenOwner,
  getUserPermissions,
  getHeaderAuthConfig,
  getUserByUsername,
  logAuthAudit
} = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

function extractBearerToken(authHeader) {
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return null;
  }

  return match[1].trim();
}

function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') {
    return null;
  }

  let value = ip.trim();
  if (!value) {
    return null;
  }

  if (value.startsWith('::ffff:')) {
    value = value.slice(7);
  }

  return net.isIP(value) ? value : null;
}

function parseRemoteIpHeader(req) {
  const xForwardedForValue = req.headers['x-forwarded-for'];
  if (xForwardedForValue) {
    const text = Array.isArray(xForwardedForValue) ? xForwardedForValue[0] : xForwardedForValue;
    if (text && typeof text === 'string') {
      const leftMostValue = text.split(',')[0].trim();
      const normalized = normalizeIp(leftMostValue);
      if (normalized) {
        return normalized;
      }
    }
  }

  const candidates = ['remote_ip', 'remote-ip', 'x-remote-ip'];

  for (const headerName of candidates) {
    const rawValue = req.headers[headerName];
    if (!rawValue) {
      continue;
    }

    const text = Array.isArray(rawValue) ? rawValue[0] : rawValue;
    if (!text || typeof text !== 'string') {
      continue;
    }

    const firstValue = text.split(',')[0].trim();
    const normalized = normalizeIp(firstValue);
    if (normalized) {
      return normalized;
    }
  }

  return null;
}

function ipv4ToBigInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8n) + BigInt(parseInt(octet, 10)), 0n);
}

function ipv6ToBigInt(ip) {
  let input = ip;
  if (input === '::') {
    return 0n;
  }

  const hasCompression = input.includes('::');
  let left = [];
  let right = [];

  if (hasCompression) {
    const parts = input.split('::');
    left = parts[0] ? parts[0].split(':') : [];
    right = parts[1] ? parts[1].split(':') : [];
  } else {
    left = input.split(':');
  }

  const normalized = [];
  normalized.push(...left);

  if (hasCompression) {
    const missing = 8 - (left.length + right.length);
    for (let index = 0; index < missing; index += 1) {
      normalized.push('0');
    }
    normalized.push(...right);
  }

  if (normalized.length !== 8) {
    return null;
  }

  let result = 0n;
  for (const segment of normalized) {
    const parsed = parseInt(segment || '0', 16);
    if (Number.isNaN(parsed) || parsed < 0 || parsed > 0xffff) {
      return null;
    }
    result = (result << 16n) + BigInt(parsed);
  }

  return result;
}

function ipToBigInt(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    return { version, value: ipv4ToBigInt(ip) };
  }
  if (version === 6) {
    const value = ipv6ToBigInt(ip);
    if (value === null) {
      return null;
    }
    return { version, value };
  }
  return null;
}

function isIpAllowedByEntry(ip, entry) {
  if (!entry) {
    return false;
  }

  const trimmed = entry.trim();
  if (!trimmed) {
    return false;
  }

  if (!trimmed.includes('/')) {
    const normalizedEntryIp = normalizeIp(trimmed);
    return !!normalizedEntryIp && normalizedEntryIp === ip;
  }

  const [networkRaw, prefixRaw] = trimmed.split('/');
  const network = normalizeIp(networkRaw);
  const prefix = parseInt(prefixRaw, 10);

  if (!network || Number.isNaN(prefix)) {
    return false;
  }

  const ipParsed = ipToBigInt(ip);
  const networkParsed = ipToBigInt(network);
  if (!ipParsed || !networkParsed || ipParsed.version !== networkParsed.version) {
    return false;
  }

  const bitLength = ipParsed.version === 4 ? 32 : 128;
  if (prefix < 0 || prefix > bitLength) {
    return false;
  }

  const hostBits = BigInt(bitLength - prefix);
  const mask = prefix === 0 ? 0n : ((1n << BigInt(bitLength)) - 1n) ^ ((1n << hostBits) - 1n);
  return (ipParsed.value & mask) === (networkParsed.value & mask);
}

function isRemoteIpAllowed(remoteIp, allowedRemoteIpsText) {
  if (!remoteIp || !allowedRemoteIpsText) {
    return false;
  }

  const entries = allowedRemoteIpsText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  if (entries.length === 0) {
    return false;
  }

  return entries.some((entry) => isIpAllowedByEntry(remoteIp, entry));
}

function getHeaderValue(req, headerName) {
  if (!headerName) {
    return null;
  }

  const rawValue = req.headers[headerName.toLowerCase()];
  if (!rawValue) {
    return null;
  }

  const text = Array.isArray(rawValue) ? rawValue[0] : rawValue;
  if (!text || typeof text !== 'string') {
    return null;
  }

  return text.trim();
}

function getSourceIp(req) {
  const headerIp = parseRemoteIpHeader(req);
  if (headerIp) {
    return headerIp;
  }

  const directIp = normalizeIp(req.ip);
  if (directIp) {
    return directIp;
  }

  return typeof req.ip === 'string' && req.ip.trim() ? req.ip.trim() : null;
}

function getCommonHeaderInfo(req) {
  return {
    userAgent: getHeaderValue(req, 'user-agent'),
    xForwardedFor: getHeaderValue(req, 'x-forwarded-for'),
    remoteIp: getHeaderValue(req, 'remote_ip') || getHeaderValue(req, 'remote-ip') || getHeaderValue(req, 'x-remote-ip')
  };
}

// Map internal authType to display names
function getAuthTypeDisplayName(internalAuthType) {
  switch (internalAuthType) {
    case 'password':
      return 'password';
    case 'bearer':
      return 'bearer';
    case 'header':
      return 'header';
    default:
      return 'unauthenticated';
  }
}

// Helper function to log audit events with common fields auto-populated
function logAuditEvent(req, {
  success,
  event,
  internalAuthType,
  user = null,
  failureReason = null,
  additionalDetails = {},
  responseStatus,
  responseBody
}) {
  try {
    const sourceIp = getSourceIp(req);
    const requestPath = req.originalUrl || req.url;
    const headerInfo = getCommonHeaderInfo(req);
    
    // Add authorization scheme if present
    const authHeader = req.headers.authorization;
    const httpHeaders = {
      ...headerInfo,
      authorizationScheme: authHeader ? (authHeader.startsWith('Bearer ') ? 'Bearer' : null) : null
    };
    
    logAuthAudit({
      success,
      authType: getAuthTypeDisplayName(internalAuthType),
      userId: user?.id || user?.userId || null,
      username: user?.username || null,
      roleName: user?.role_name || null,
      sourceIp,
      requestMethod: req.method,
      requestPath,
      httpHeaders,
      failureReason,
      details: {
        event,
        outcome: success ? 'succeeded' : 'failed',
        ...additionalDetails
      },
      responseData: { status: responseStatus, body: responseBody }
    });
  } catch (err) {
    console.error('Failed to write auth audit event:', err);
  }
}

function tryHeaderAuth(req) {
  const headerAuthConfig = getHeaderAuthConfig();
  if (!headerAuthConfig.enabled) {
    return { attempted: false, user: null, error: null };
  }

  const usernameHeaderValue = getHeaderValue(req, headerAuthConfig.usernameHeader);
  if (!usernameHeaderValue) {
    return { attempted: false, user: null, error: null };
  }

  const remoteIp = parseRemoteIpHeader(req);
  if (!remoteIp || !isRemoteIpAllowed(remoteIp, headerAuthConfig.allowedRemoteIps)) {
    const responsePayload = { error: 'Unauthorized: remote_ip not allowed for header authentication' };
    logAuditEvent(req, {
      success: false,
      event: 'header_auth_login',
      internalAuthType: 'header',
      user: { username: usernameHeaderValue },
      failureReason: 'remote_ip_not_allowed',
      additionalDetails: { allowedRemoteIpsConfigured: true },
      responseStatus: 401,
      responseBody: responsePayload
    });

    return {
      attempted: true,
      user: null,
      error: 'Unauthorized: remote_ip not allowed for header authentication'
    };
  }

  const user = getUserByUsername(usernameHeaderValue);
  if (!user || user.status !== 'active') {
    const responsePayload = { error: 'Unauthorized: Invalid user in authentication header' };
    logAuditEvent(req, {
      success: false,
      event: 'header_auth_login',
      internalAuthType: 'header',
      user: { username: usernameHeaderValue },
      failureReason: 'invalid_or_inactive_header_user',
      responseStatus: 401,
      responseBody: responsePayload
    });

    return {
      attempted: true,
      user: null,
      error: 'Unauthorized: Invalid user in authentication header'
    };
  }

  const permissions = getUserPermissions(user.id).map((permission) => permission.name);

  return {
    attempted: true,
    user: {
      userId: user.id,
      username: user.username,
      permissions,
      authType: 'header'
    },
    error: null
  };
}

// Middleware to verify JWT token
function authMiddleware(req, res, next) {
  const headerAuthResult = tryHeaderAuth(req);
  if (headerAuthResult.user) {
    req.user = headerAuthResult.user;
    return next();
  }

  if (headerAuthResult.attempted && headerAuthResult.error) {
    return res.status(401).json({ error: headerAuthResult.error });
  }

  const bearerToken = extractBearerToken(req.headers.authorization);

  if (bearerToken) {
    const user = getApiTokenOwner(bearerToken);
    if (!user || user.status !== 'active') {
      const responsePayload = { error: 'Unauthorized: Invalid or expired bearer token' };
      logAuditEvent(req, {
        success: false,
        event: 'bearer_token_login',
        internalAuthType: 'bearer',
        failureReason: 'invalid_or_expired_bearer_token',
        responseStatus: 401,
        responseBody: responsePayload
      });

      return res.status(401).json({ error: 'Unauthorized: Invalid or expired bearer token' });
    }

    const permissions = getUserPermissions(user.id).map((permission) => permission.name);
    req.user = {
      userId: user.id,
      username: user.username,
      permissions,
      authType: 'bearer'
    };

    return next();
  }

  const token = req.cookies?.token;

  if (!token) {
    const responsePayload = { error: 'Unauthorized: No token provided' };
    logAuditEvent(req, {
      success: false,
      event: 'cookie_token_auth',
      internalAuthType: 'password',
      failureReason: 'missing_token',
      responseStatus: 401,
      responseBody: responsePayload
    });

    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = {
      ...decoded,
      authType: 'password'
    };
    next();
  } catch (err) {
    const responsePayload = { error: 'Unauthorized: Invalid token' };
    logAuditEvent(req, {
      success: false,
      event: 'cookie_token_auth',
      internalAuthType: 'password',
      failureReason: 'invalid_cookie_token',
      responseStatus: 401,
      responseBody: responsePayload
    });

    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
}

// Middleware to verify admin/permission
function requirePermission(permissionName) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Check if user has admin permission or specific permission
    if (req.user.permissions.includes('administration') || req.user.permissions.includes(permissionName)) {
      next();
    } else {
      return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
    }
  };
}

// Middleware to require admin
function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  if (!req.user.permissions.includes('administration')) {
    return res.status(403).json({ error: 'Forbidden: Admin access required' });
  }

  next();
}

function generateToken(user, permissions) {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username,
      permissions: permissions.map(p => p.name)
    },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

module.exports = {
  authMiddleware,
  requirePermission,
  requireAdmin,
  tryHeaderAuth,
  generateToken,
  JWT_SECRET
};
