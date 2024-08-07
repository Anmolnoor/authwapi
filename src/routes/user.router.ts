import express from 'express';
import { Auth, User } from '../controllers';
// import { uploadSingleImageInAWSS3Middleware } from 'controllers/s3.controller';
import { upload } from '../utils/multerService';

const router = express.Router();

router.get('/:username', User.getPublicProfile);

router.post(
  '/upload-image',
  Auth.protect,
  upload.fields([{ name: 'image', maxCount: 1 }]),
  // uploadSingleImageInAWSS3Middleware,   // -- this is the old way of doing it
  User.uploadImage
);

export default router;
