class CustomErrorHandler extends Error {
  statusCode: number;
  status: string;
  isOperational: boolean;
  constructor(msg: string, statusCode: number) {
    super(msg);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

export default CustomErrorHandler;
