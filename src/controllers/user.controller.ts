import { NextFunction, Request, Response } from 'express';
import User from '../models/user.model';
import Err from '../utils/errorHandler';
import {
  CatchAsync,
  FileNameGenerator,
  ResponseGenerator,
} from '../utils/helper';
import { s3UploadSingle } from '../utils/s3services';

const uploadImage = CatchAsync(async (req, res, next) => {
  console.log('it is in the uploadImage controller');

  if (req.files === null || req.files === undefined) {
    next(new Err('SomeThing went wrong!! try again', 500));
  }

  // handle Images
  const imageName = FileNameGenerator(req.files?.image[0]);

  await s3UploadSingle(req.files.image[0], imageName);
  req.imageName = imageName;

  await User.updateOne({ _id: req.id }, { avatar: imageName });

  ResponseGenerator(res, 200, { msg: 'Image uploaded successfully' });
});

// return user details with social links
const getUserDetails = CatchAsync(async (req, res, next) => {
  const user = await User.findById(req.id).select([
    '-password',
    '-__v',
    '-passwordChangedAt',
    '-passwordResetToken',
    '-passwordResetExpires',
    '-active',
    '-passwordConfirm',
  ]);
  ResponseGenerator(res, 200, user);
});

const UserController = { uploadImage, getUserDetails };

export default UserController;
