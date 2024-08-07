import express from 'express';
import { Auth } from '../controllers';

const router = express.Router();

router.post('/register', Auth.register);

router.post('/login', Auth.login);

router.patch('/reset-password/:token', Auth.resetPassword);

router.post('/forgot-password', Auth.forgotPassword);

router.get('/logout', Auth.logout);

export default router;
