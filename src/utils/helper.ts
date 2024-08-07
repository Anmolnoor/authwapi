import { NextFunction, Request, Response } from 'express';
import { randomString } from './encryptDecrypt';

const CatchAsync = (
  fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>
) => {
  return (req: Request, res: Response, next: NextFunction) => {
    fn(req, res, next).catch((err) => {
      next(err);
    });
  };
};

// Image name generator for the s3 bucket
const FileNameGenerator = (image: any): string => {
  const ext: string = image.mimetype.split('/')[1];
  return `${randomString(32)}.${ext}`;
};

const ResponseGenerator = (
  res: Response,
  statusCode: number,
  data: any
): Response<any, Record<string, any>> => {
  return res.status(statusCode).json({
    status: `${statusCode}`.startsWith('2') ? 'success' : 'fail',
    data,
  });
};

export { CatchAsync, ResponseGenerator, FileNameGenerator };
