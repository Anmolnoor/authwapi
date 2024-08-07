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
