import { ErrorRequestHandler, NextFunction, Request, Response } from 'express';
import Log from '../utils/logger';

interface Errr extends ErrorRequestHandler {
  statusCode: number;
  status: string;
  message: string;
  stack: string;
  isOperational: boolean;
  code?: string;
  path?: string[];
  name?: string;
  issues?: object;
  meta?: {
    target: string[];
    cause: string;
  };
  keyValue: unknown;
}

const sendDevErr = (err: Errr, res: Response) => {
  Log.error({
    status: err.status,
    msg: err.message,
    errstack: err.stack,
    err,
  });
  return res.status(err.statusCode).json({
    status: err.status,
    msg: err.message,
    errstack: err.stack,
    err,
  });
};

const sendProdErr = (err: Errr, res: Response): void => {
  // --- Only Operational and trusted error message sending to the user
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      msg: err.message,
    });
  } else {
    Log.error({
      status: err.status,
      msg: err.message,
      errstack: err.stack,
      err,
    });
    //   --- sending the generic msg
    res.status(err.statusCode).json({
      status: 500,
      msg: 'Something went very Wrong',
    });
  }
};

const globalErrorHandler = (
  err: Errr,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  err.statusCode = err.statusCode ?? 500;
  err.status = err.status ?? 'error';
  if (err.name === 'TokenExpiredError') {
    err.isOperational = true;
    err.message = 'Token expired. Please login again';
    err.statusCode = 401;
  }
  if (err.name === 'JsonWebTokenError') {
    err.isOperational = true;
    err.message = 'Invalid Token. Please login again';
    err.statusCode = 401;
  }
  process.env.NODE_ENV === 'development'
    ? sendDevErr(err, res)
    : sendProdErr(err, res);

  next();
};

export default globalErrorHandler;
