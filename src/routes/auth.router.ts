import express from 'express';
import { Auth } from '../controllers';

const router = express.Router();

router.post('/register', Auth.register);

router.post('/login', Auth.login);

router.patch('/reset-password/:token', Auth.resetPassword);

router.post('/forget-password', Auth.forgotPassword);

router.get('/logout', Auth.logout);

// New endpoints for service-to-service auth
router.post('/validate-token', Auth.validateToken);

router.post('/service-login', Auth.serviceLogin);

router.get('/user-info', Auth.protect, Auth.getUserInfo);

// Handle availability under auth
router.post('/check-handle', Auth.getHandle);
router.get('/check-handle/:handle?', Auth.getHandleGet);

export default router;
