import { Types } from 'mongoose';

// ---- getting id from Mongoose types ----
export type ID = Types.ObjectId;

// ---- service type ----
export enum service {
  Amend = 'Amend',
  notes = 'Notes',
  food = 'Food',
}

export enum permissions {
  create = 'create',
  read = 'read',
  update = 'update',
  delete = 'delete',
  export = 'export',
  import = 'import',
  print = 'print',
  download = 'download',
  upload = 'upload',
  share = 'share',
  view = 'view',
}

export type IServicePermissions = {
  [key in service]: permissions[];
};

// user type
export interface IUser {
  _id: ID;
  handle: string;
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
  service: service[];
  permissions: IServicePermissions;
}

// ---- Multer types ----

export type UploadedFile = Express.Multer.File;

export type F = Record<string, File[]>;

export type UploadedFiles = File[];
