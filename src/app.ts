import dotenv from 'dotenv';
import express, { Express } from 'express';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import xss from 'xss-clean';
import cors from 'cors';
import prometheus from 'prom-client';

// ---- module alias ----
import 'module-alias/register';

// import functions here
import CEH from './utils/errorHandler';
import { globalErrorHandler } from './controllers';

//  --- routers Import ---
import route from './routes/router';

import { auth, User } from './routes';

//  ---   env   ---
dotenv.config({ path: './.env' });

const app: Express = express();

// trust proxy from vercel
app.set('trust proxy', 1);

// cors
app.use(cors());

// XSS-Clean
app.use(xss());

// Set Security HTTP Headers
app.use(helmet());

// // Development Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('short'));
}

const FixedTime = 60 * 60 * 1000;
// Limiting request from same IP
const limiter = rateLimit({
  max: 500,
  windowMs: FixedTime,
  message: 'Too many request from this IP, Please try again in an Hour!',
});

app.use('/', limiter);

// Body parser and reading data from the body into req.body
// { limit: '4096kb' }
app.use(express.json({ limit: '4096kb' }));

// cookie parser
app.use(cookieParser());

// Create metrics
const httpRequestDurationMicroseconds = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
});

const totalRequests = new prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

// --- Routers ---
// --- API ---
app.use('/', (req, res) => {
  res.json({
    status: 'up',
    timestamp: new Date(),
    uptime: process.uptime(),
  });
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', prometheus.register.contentType);
  res.end(await prometheus.register.metrics());
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'up',
    timestamp: new Date(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
  });
});
// -- API-v1.0.0 --
app.use('/api/test', route);
app.use('/api/v1/auth', auth);
app.use('/api/v1/user', User);

// --- route not found error handling ---
app.use('*', (req, res, next) => {
  next(new CEH(`Can't found ${req.originalUrl} on this server!!!`, 404));
});

// --- Global error handling middleware ---
app.use(globalErrorHandler);

export default app;
