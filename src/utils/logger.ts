import { createLogger, transports, format } from 'winston';
const { combine, colorize, timestamp, align, printf } = format;

/* 

// this is how you can use this logger
// Logger.info('info');
// Logger.error('error');
// Logger.warn('warn');
// Logger.debug('debug');
// Logger.verbose('verbose');
// Logger.silly('silly');

**/

const logFormat = printf(({ timestamp, level, message }) => {
  return `[${timestamp}] ${level}: ${message}`;
});

const Log = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    colorize({ all: true }),
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    align(),
    logFormat
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'app.log' }),
  ],
  exceptionHandlers: [new transports.File({ filename: 'exceptions.log' })],
  rejectionHandlers: [new transports.File({ filename: 'rejections.log' })],
});

export default Log;
