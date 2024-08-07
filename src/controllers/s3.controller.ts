import { randomString } from '../utils/encryptDecrypt';
import Err from '../utils/errorHandler';
import {
  CatchAsync,
  FileNameGenerator,
  ResponseGenerator,
} from '../utils/helper';

import { s3Delete, s3UploadSingle } from '../utils/s3services';

// --- usefull functions ---

// Image name generator for the s3 bucket

// const MultiFileNameGenerator = (files: any[]): string[] => {
//   return files.map((image) => {
//     const ext: string = image.originalname?.split('.')[1];
//     return `${randomString(32)}.${ext}`;
//   });
// };

const uploadSingleImageInAWSS3Middleware = CatchAsync(
  async (req, res, next) => {
    if (req.files !== undefined) {
      next(new Err('SomeThing went wrong!! try again', 500));
    }

    // handle Images
    const imageName = FileNameGenerator(req.files?.image[0]);

    const t = await s3UploadSingle(req.files.image[0], imageName);
    req.imageName = imageName;

    console.log(t, 't');

    next();
  }
);

const uploadSingleImageInAWSS3 = CatchAsync(async (req, res, next) => {
  if (req.file !== undefined) {
    next(new Err('SomeThing went wrong!! try again', 500));
  }

  // handle Images
  const imageName = FileNameGenerator(req.files.image[0]);
  await s3UploadSingle(req.files.image[0], imageName);

  ResponseGenerator(res, 201, { name: imageName });
});

const deleteUploadedImagesInAWSS3 = CatchAsync(async (req, res, next) => {
  const image = req.body.image;
  await s3Delete(image);
  ResponseGenerator(res, 204, { msg: 'Images deleted successfully' });
});

export {
  uploadSingleImageInAWSS3,
  uploadSingleImageInAWSS3Middleware,
  deleteUploadedImagesInAWSS3,
};
