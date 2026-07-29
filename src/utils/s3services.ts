import {
  DeleteObjectCommand,
  DeleteObjectCommandOutput,
  PutObjectCommand,
  PutObjectCommandOutput,
  S3Client,
} from '@aws-sdk/client-s3';
import { UploadedFile, UploadedFiles } from 'types/model.type';

// details for the s3 client to connect with the S3 bucket
// one shared client, reused by every operation below
const s3client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? '',
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '',
  },
});

export const s3UploadMultipleFiles = async (
  files: UploadedFiles,
  names: string[]
): Promise<PutObjectCommandOutput[]> => {
  // get the files from the req and create a workable formate
  const params = files.map((file: any, i: number) => {
    return {
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: `uploads/${names[i]}`,
      Body: file?.buffer,
    };
  });
  // create a promise to catch all the results at one time and return.
  const res = await Promise.all(
    params.map(
      async (param) => await s3client.send(new PutObjectCommand(param))
    )
  );
  return res;
};

export const s3UploadSingle = async (
  file: UploadedFile,
  name: string
): Promise<PutObjectCommandOutput> => {
  // get the file from the req and create a workable formate
  const param = {
    Bucket: process.env.AWS_BUCKET_NAME,
    Key: `uploads/${name}`,
    Body: file?.buffer,
  };

  // create a promise to catch all the results at one time and return.
  const res = await s3client.send(new PutObjectCommand(param));

  return res;
};

export const s3Delete = async (
  files: string[]
): Promise<DeleteObjectCommandOutput[]> => {
  const params = files.map((item) => {
    return {
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: `uploads/${item}`,
    };
  });

  const res = await Promise.all(
    params.map(
      async (param) => await s3client.send(new DeleteObjectCommand(param))
    )
  );

  return res;
};
