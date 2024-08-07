import value from 'xss-clean';
import { IUser } from 'types/model.type';
import {
  passwordEncryptor,
  passwordValidator,
  resetTokenGenerator,
} from '../utils/encryptDecrypt';
import mongoose, { Query, Schema } from 'mongoose';
import CHE from '../utils/errorHandler';

const TOKEN_EXPIRATION_TIME_MS = 10 * 60 * 1000;

const userSchema = new Schema<IUser>(
  {
    firstName: {
      type: String,
      required: [true, 'Please provide a first name'],
      trim: true,
      maxlength: 32,
    },
    lastName: {
      type: String,
      required: [true, 'Please provide a last name'],
      trim: true,
      maxlength: 32,
    },
    username: {
      type: String,
      trim: true,
      unique: true,
      maxlength: 64,
    },
    email: {
      type: String,
      required: [true, 'Please provide an email'],
      trim: true,
      maxlength: 32,
      unique: true,
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      trim: true,
      maxlength: 32,
    },
    image: {
      type: String,
      default: undefined,
    },
    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password'],
      trim: true,
      maxlength: 32,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
    },
    passwordChangedAt: {
      type: Date,
    },
    isActive: {
      type: Boolean,
      default: true,
      select: false,
    },
    resetToken: { type: String },
    resetTokenTimer: { type: Date },
  },
  {
    // methods
    methods: {
      async correctPassword(candidatePassword: string, userPassword: string) {
        return await passwordValidator(candidatePassword, userPassword);
      },
      changedPasswordAfter(JWTTime: number, passwordChangedAt: Date) {
        const passwordChangedTimestamp = passwordChangedAt?.getTime() ?? null;

        if (passwordChangedTimestamp !== null) {
          const timeStampInSeconds = Math.floor(
            passwordChangedTimestamp / 1000
          );
          return JWTTime < timeStampInSeconds;
        }
        return false;
      },
      /**
       * Generates a random password reset token, stores the encrypted version,
       * sets the expiration timer, and returns the plain token.
       *
       * @returns {Promise<string>} The plain text reset token.
       */
      async createRandomPasswordToken(): Promise<string> {
        try {
          const { encryptedResetToken, resetToken } = resetTokenGenerator();

          this.resetToken = encryptedResetToken;
          this.resetTokenTimer = new Date(
            Date.now() + TOKEN_EXPIRATION_TIME_MS
          );

          return resetToken;
        } catch (error) {
          // Handle potential errors
          console.error('Error generating reset token:', error);
          throw new Error('Failed to generate reset token');
        }
      },
    },
  }
);

// middleware or hooks to run before saving the document to the database
// encrypt the password
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  if (this.password !== this.passwordConfirm) {
    next(new CHE("password does't match", 400));
    return;
  }
  // hash the password with the cost of 12 in bcryptjs
  this.password = await passwordEncryptor(this.password);
  // delete the passwordConfirm field
  this.passwordConfirm = 'undefined';
  next();
});

// update the password modified in passwordChangedAy
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = new Date(Date.now() - 1000);
  next();
});

userSchema.pre<Query<any, any>>(/^find/, function (next) {
  //  this point to the current query
  this.find({ active: { $ne: false } });
  next();
});

const User = mongoose.models.User || mongoose.model<IUser>('User', userSchema);

export default User;
