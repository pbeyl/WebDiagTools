const jwt = require('jsonwebtoken');
const { getApiTokenOwner, getUserPermissions } = require('./db');

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

// Middleware to verify JWT token
function authMiddleware(req, res, next) {
  const bearerToken = extractBearerToken(req.headers.authorization);

  if (bearerToken) {
    const user = getApiTokenOwner(bearerToken);
    if (!user || user.status !== 'active') {
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
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
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
  generateToken,
  JWT_SECRET
};
