import bcrypt from 'bcryptjs';
import crypto from 'crypto';

// reset token generator and encryptor
const randomString = (length: number): string => {
  return crypto.randomBytes(length).toString('hex');
};

// encrypt the reset token
const encryptToken = (resetToken: string): string => {
  const encryptedToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  return encryptedToken;
};

// generate the reset token
const resetTokenGenerator = (): {
  encryptedResetToken: string;
  resetToken: string;
} => {
  const resetToken = randomString(32);
  const encryptedResetToken = encryptToken(resetToken);
  return { encryptedResetToken, resetToken };
};

// password encryptor and validator
const passwordEncryptor = async (password: string): Promise<string> => {
  const encryptedPassword = await bcrypt.hash(password, 12);
  return encryptedPassword;
};

const passwordValidator = async (
  password: string,
  userpassword: string
): Promise<boolean> => {
  const compared = await bcrypt.compare(userpassword, password);
  return compared;
};

export {
  resetTokenGenerator,
  encryptToken,
  randomString,
  passwordEncryptor,
  passwordValidator,
};
