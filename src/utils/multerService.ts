import { Request } from 'express';
import multer, { MulterError, FileFilterCallback } from 'multer';

const storage = multer.memoryStorage();

const fileFilter = (req: Request, file: any, cb: FileFilterCallback): void => {
  if (file.mimetype.split('/')[0] === 'image') {
    cb(null, true);
    return;
  }
  cb(new MulterError('LIMIT_UNEXPECTED_FILE'));
};

export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 1 * 1024 ** 2,
    files: 1,
  },
});
