"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const token_1 = require("../services/token");
const user_1 = require("../services/user");
const auth_1 = require("../middleware/auth");
const router = (0, express_1.Router)();
// Conditional authentication middleware for registration
const conditionalAuth = (req, res, next) => {
    const userCount = user_1.UserService.getUserCount();
    if (userCount === 0) {
        next(); // Skip authentication for first user
    }
    else {
        (0, auth_1.authenticate)(req, res, next); // Require auth for subsequent
    }
};
// Unified registration endpoint
router.post('/auth/register', conditionalAuth, async (req, res) => {
    try {
        const { username, password } = req.body;
        // First user registration (no auth required)
        const userCount = user_1.UserService.getUserCount();
        if (userCount === 0) {
            const user = await user_1.UserService.createUser(username, password);
            const token = token_1.TokenService.generateAuthToken(user.id, 'admin');
            res.status(201).json({
                token,
                user: {
                    id: user.id,
                    username: user.username,
                    role: 'admin'
                }
            });
            return;
        }
        // Subsequent registrations require admin auth
        if (!req.user || req.user.role !== 'admin') {
            res.status(403).json({ error: 'Admin privileges required' });
            return;
        }
        const user = await user_1.UserService.createUser(username, password, req.user.id // Pass the authenticated admin user
        );
        res.status(201).json({
            id: user.id,
            username: user.username,
            role: user.role
        });
    }
    catch (error) {
        const statusCode = error.message.includes('already exists') ? 409 : 400;
        res.status(statusCode).json({
            error: error.message,
            code: error.message.replace(/\s+/g, '_').toUpperCase()
        });
    }
});
// Login endpoint
router.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await user_1.UserService.authenticate(username, password);
        const token = token_1.TokenService.generateAuthToken(user.id, user.role);
        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });
    }
    catch (error) {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});
// User listing endpoint
router.get('/auth/users', auth_1.authenticate, async (req, res) => {
    try {
        // Type-safe access to user data
        if (!req.user || req.user.role !== 'admin') {
            res.status(403).json({ error: 'Admin privileges required' });
            return;
        }
        const users = await user_1.UserService.listUsers();
        res.json(users);
    }
    catch (error) {
        res.status(403).json({ error: error.message });
    }
});
exports.default = router;
//# sourceMappingURL=auth.js.map