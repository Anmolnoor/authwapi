import { Types } from 'mongoose';

// ---- getting id from Mongoose types ----
export type ID = Types.ObjectId;

// user type
export interface IUser {
  _id: ID;
  firstName: string;
  lastName: string;
  username: string;
  email: string;
  password: string;
  passwordConfirm: string;
  phone: number;
  image: string;
  createdAt: Date;
  updatedAt: Date;
  passwordChangedAt: Date;
  isActive: boolean;
  resetToken: string;
  resetTokenTimer: Date;
}

// ---- Multer types ----

export type UploadedFile = Express.Multer.File;

export type F = Record<string, File[]>;

export type UploadedFiles = File[];

// ---- sharp types ----

declare module 'sharp' {
  interface Sharp {
    resize(width?: number, height?: number, options?: any): Sharp;
    toBuffer(): Promise<Buffer>;
    toFile(path: string): Promise<void>;
    jpeg(options?: any): Sharp;
    png(options?: any): Sharp;
    toFormat(format: string, options?: any): Sharp;
  }

  function sharp(input?: string | Buffer): Sharp;
  export = sharp;
}

// ---- xss-clean types ----

declare module 'xss-clean' {
  const xss: any;

  export default xss;
}

export type Sharp = typeof sharp;
