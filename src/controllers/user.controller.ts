import { NextFunction, Request, Response } from 'express';
import User from '../models/user.model';
import Err from '../utils/errorHandler';
import {
  CatchAsync,
  FileNameGenerator,
  ResponseGenerator,
} from '../utils/helper';
import { s3UploadSingle } from '../utils/s3services';
import sharp from 'sharp';

const uploadImage = CatchAsync(async (req, res, next) => {
  console.log('it is in the uploadImage controller');

  if (req.files === null || req.files === undefined) {
    return next(new Err('SomeThing went wrong!! try again', 500));
  }

  // Validate file type
  const allowedTypes = ['image/jpeg', 'image/png', 'image/heif'];
  const fileType = req.files.image[0].mimetype;

  if (!allowedTypes.includes(fileType)) {
    return next(
      new Err(
        'Invalid file type. Only JPG, PNG, and HEIF images are allowed',
        400
      )
    );
  }

  let processedBuffer = req.files.image[0].buffer;
  const originalSize = req.files.image[0].size; // Get original file size

  // Convert HEIF to PNG if necessary and compress all images
  try {
    const sharpInstance = sharp(req.files.image[0].buffer);

    if (fileType === 'image/heif') {
      // Convert HEIF to PNG
      sharpInstance.toFormat('png', {
        quality: 80,
        compressionLevel: 9,
      });
      req.files.image[0].mimetype = 'image/png';
    } else if (fileType === 'image/jpeg') {
      // Compress JPEG
      sharpInstance.jpeg({
        quality: 80,
        mozjpeg: true,
      });
    } else if (fileType === 'image/png') {
      // Compress PNG
      sharpInstance.toFormat('png', {
        quality: 80,
        compressionLevel: 9,
      });
    }

    // Resize if image is too large (optional)
    sharpInstance.resize(1920, 1080, {
      fit: 'inside',
      withoutEnlargement: true,
    });

    processedBuffer = await sharpInstance.toBuffer();
  } catch (error) {
    return next(new Err('Error processing image', 500));
  }

  // handle Images (now using processed buffer)
  const imageName = FileNameGenerator(req.files?.image[0]);

  await s3UploadSingle(
    { ...req.files.image[0], buffer: processedBuffer },
    imageName
  );
  req.imageName = imageName;

  await User.updateOne({ _id: req.id }, { image: imageName });

  ResponseGenerator(res, 200, {
    msg: 'Image uploaded successfully',
    imageName: imageName,
    originalSize: originalSize,
    compressedSize: processedBuffer.length,
    compressionRatio:
      (((originalSize - processedBuffer.length) / originalSize) * 100).toFixed(
        2
      ) + '%',
    fileType: fileType,
    allowedTypes: allowedTypes,
  });
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
