// authMiddleware.js
const jwt = require('jsonwebtoken');

// Optional hook for server-side token revocation (e.g. a `token_version`
// column bumped on password change). Not wired up by default so this file
// stays a drop-in replacement without any schema/index.js changes. To enable:
//
//   const authenticateToken = require('./authMiddleware');
//   authenticateToken.setTokenVersionChecker(async (userId, tokenVersion) => {
//     const user = await db.getUser(userId);
//     return user.token_version === tokenVersion;
//   });
//
// and make sure the JWT payload includes `tokenVersion` at issuance time.
let tokenVersionChecker = null;

function setTokenVersionChecker(fn) {
    tokenVersionChecker = fn;
}

async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: "Access Denied" });
    }

    try {
        // Pin the accepted algorithm(s) explicitly. Without this, jwt.verify()
        // trusts whatever algorithm is embedded in the token itself. That's
        // the classic opening for algorithm-confusion attacks if this secret
        // is ever reused alongside an asymmetric key, or if the library's
        // permissive defaults ever change. Costs nothing, closes the door.
        const verifiedUser = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
        });

        // Optional server-side revocation check. No-op until a checker is
        // registered via setTokenVersionChecker(), so this is safe to ship
        // as-is and wire up later.
        if (tokenVersionChecker) {
            const userId = verifiedUser.id ?? verifiedUser.sub;
            const stillValid = await tokenVersionChecker(userId, verifiedUser.tokenVersion);
            if (!stillValid) {
                return res.status(403).json({ success: false, message: "Token has been revoked" });
            }
        }

        req.user = verifiedUser;
        next();
    } catch (error) {
        return res.status(403).json({ success: false, message: "Invalid Token" });
    }
}

module.exports = authenticateToken;
module.exports.setTokenVersionChecker = setTokenVersionChecker;
