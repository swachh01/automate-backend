// authMiddleware.js
const jwt = require('jsonwebtoken');

// 401 = "token missing / expired / invalid -> client should refresh or log in".
// The Android Authenticator only refreshes on 401, so never return 403 for these cases.
async function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: "Access Denied" });
    }

    try {
        const verifiedUser = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
        });
        req.user = verifiedUser;
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: error.name === 'TokenExpiredError' ? "Token expired" : "Invalid Token"
        });
    }
}

module.exports = authenticateToken;
