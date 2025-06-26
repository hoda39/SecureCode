import { Router } from 'express';
import { Request, Response, NextFunction } from 'express';
import { TokenService } from '../services/token';
import { UserService } from '../services/user';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';

const router = Router();

// Conditional authentication middleware for registration
const conditionalAuth = (req: Request, res: Response, next: NextFunction) => {
  const userCount = UserService.getUserCount();
  if (userCount === 0) {
    next(); // Skip authentication for first user
  } else {
    authenticate(req as AuthenticatedRequest, res, next); // Require auth for subsequent
  }
};

// Unified registration endpoint
router.post('/auth/register', conditionalAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { username, password } = req.body;
    
    // First user registration (no auth required)
    const userCount = UserService.getUserCount();
    if (userCount === 0) {
      const user = await UserService.createUser(username, password);
      const token = TokenService.generateAuthToken(user.id, 'admin');
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

    const user = await UserService.createUser(
      username,
      password,
      req.user.id // Pass the authenticated admin user
    );
    
    res.status(201).json({
      id: user.id,
      username: user.username,
      role: user.role
    });
  } catch (error: any) {
    const statusCode = error.message.includes('already exists') ? 409 : 400;
    res.status(statusCode).json({ 
      error: error.message,
      code: error.message.replace(/\s+/g, '_').toUpperCase()
    });
    }
});

// Login endpoint
router.post('/auth/login', async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    const user = await UserService.authenticate(username, password);
    const token = TokenService.generateAuthToken(user.id, user.role);
    
    res.json({ 
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
  } catch (error: any) {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// User listing endpoint
router.get('/auth/users', authenticate, async (req: AuthenticatedRequest, res: Response) => {
  try {
    // Type-safe access to user data
    if (!req.user || req.user.role !== 'admin') {
      res.status(403).json({ error: 'Admin privileges required' });
      return
    }

    const users = await UserService.listUsers();
    res.json(users);
  } catch (error: any) {
    res.status(403).json({ error: error.message });
  }
});

export default router;