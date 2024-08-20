import { NextFunction, Request, Response } from 'express';
import { ResponseGenerator, CatchAsync } from '../utils/helper';
import User from '../models/user.model';
import { createTokenwithCookie, verifyJWTToken } from '../utils/jwt';
import Err from '../utils/errorHandler';
import { ID, IUser } from '../types/model.type';
import {
  encryptToken,
  randomString,
  resetTokenGenerator,
} from '../utils/encryptDecrypt';

import sendMail from '../utils/email';

declare module 'express-serve-static-core' {
  export interface Request {
    user: IUser;
    id: ID;
    files: {
      image: Express.Multer.File[];
    };
    imageName: string;
  }
}
const loginFailed = (res: Response) => {
  return ResponseGenerator(res, 401, {
    msg: 'Login Failed',
    err: 'Incorrect email or password',
  });
};

const register = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user data from the req
    const {
      email,
      username,
      password,
      passwordConfirm,
      image,
      firstName,
      lastName,
      phone,
    } = req.body;

    // TODO: validate the user data and throw an error if the data is not valid

    // create a new user
    const user = await User.create({
      email,
      username,
      password,
      passwordConfirm,
      image,
      firstName,
      lastName,
      phone,
    });

    // extra fetures that we wanna add to the user
    // create the token and send to the user
    createTokenwithCookie(user.id, res);
    ResponseGenerator(res, 201, { user });
  }
);

const login = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user details from the req
    const { username, password } = req.body;
    //TODO: validate and parse the details from the user data

    // find the user based on the email or the username
    const user = await User.findOne({
      $or: [{ email: username }, { username }],
    });

    // if user exist and validate the password and send the jwt token to the user
    if (user !== null) {
      const isAuthorized: boolean = await User.schema.methods.correctPassword(
        user.password,
        password
      );
      if (isAuthorized) {
        // create the token and send to the user
        createTokenwithCookie(user._id, res);
        return ResponseGenerator(res, 201, user);
      }
    }
    return loginFailed(res);
  }
);

const updatePassword = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user details
    const { id } = req;
    const { password, newPassword, newPasswordConfirm } = req.body;
    const user = await User.findById({ _id: id });

    if (user !== null) {
      // check if the password is correct
      const isAuthorized: boolean = await User.schema.methods.correctPassword(
        user.password,
        password
      );
      if (isAuthorized) {
        // update the password
        user.password = newPassword;
        user.passwordConfirm = newPasswordConfirm;
        // update the db with new password
        await user?.save();
        // get the user log in again by sending the jwt token again
        // create the token and send to the user
        createTokenwithCookie(id, res);
        ResponseGenerator(res, 201, {});
        return;
      }
      next(new Err('Password is incorrect', 400));
      return;
    }
    next(new Err('User does not exist', 400));
  }
);

const forgotPassword = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user details
    const { email } = req.body;
    // parse the user data and through a error if not required data
    // TODO: validate the email that came from the user

    // get the user details from the db
    const user = await User.findOne({ email });
    // if no user exist throw an error
    if (user == null) {
      next(new Err('There is no user with this E-mail address.', 404));
      return;
    }
    // create an encrypted token for the db and an reset token for the user
    const { encryptedResetToken, resetToken } = resetTokenGenerator();
    // update the db with the newly created token and the 10 minutes time limit on the reseting
    const addedTime = Date.now() + 10 * 60 * 1000;
    await User.findByIdAndUpdate(
      { _id: user?.id },
      {
        $set: {
          resetToken: encryptedResetToken,
          resetTokenTimer: new Date(addedTime),
        },
      }
    );
    // send the email to the user mail
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    const resetUrl = `${req.protocol}://${process.env.EMAIL_URL}${resetToken}`;
    const msg = `Forgot your password? Submit a PATCH request with your new password and password confirm to :\n${resetUrl}\nIf you didn't forgot your password, please ignore this email`;
    const subject = 'Your password reset token (valid for 10 minutes)';

    try {
      await sendMail({
        email,
        msg,
        subject,
      });
      // create a response for the user
      ResponseGenerator(res, 201, { msg: 'Token sent to email!' });
    } catch (error) {
      await User.findByIdAndUpdate(
        { _id: user?.id },
        {
          $set: {
            resetToken: randomString(64),
            resetTokenTimer: new Date(Date.now() - 100 * 60 * 1000),
          },
        }
      );
      next(
        new Err(
          'There was an error while sending the email. Try again later!',
          500
        )
      );
    }
  }
);

const resetPassword = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user based on the token
    const resetToken = req.params.token;
    // const parserToken = ZodValidator(resetTokenVerifier, next, resetToken);
    const encryptedResetToken = encryptToken(resetToken);

    const user = await User.findOne({ resetToken: encryptedResetToken });

    // if the token is not expired , and the user exist change the password
    if (user == null) {
      next(new Err('Token is invalid or has Expired', 400));
      return;
    }
    // update the changed password
    if (user.resetTokenTimer != null) {
      if (user.resetTokenTimer > new Date()) {
        const { password, passwordConfirm } = req.body;
        user.password = password;
        user.passwordConfirm = passwordConfirm;
        user.resetToken = randomString(64);
        user.resetTokenTimer = new Date(Date.now() - 100 * 60 * 1000);
        await user.save();
        // log the user in and send the jwt token to the user
        // create the token and send to the user
        createTokenwithCookie(user.id, res);
        ResponseGenerator(res, 201, { user });
        return;
      }
    }
    next(new Err('Token is invalid or has Expired', 400));
  }
);

const currentPasswordChange = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user details
    const { id } = req;
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;
    const user = await User.findById({ _id: id });

    if (user !== null) {
      const isAuthorized: boolean = await User.schema.methods.correctPassword(
        user.password,
        currentPassword
      );
      if (isAuthorized) {
        // update the password
        user.password = newPassword;
        user.passwordConfirm = newPasswordConfirm;
        // update the db with new password
        await user?.save();
        // get the user log in again by sending the jwt token again
        // create the token and send to the user
        createTokenwithCookie(id, res);
        ResponseGenerator(res, 201, {});
        return;
      }
      next(new Err('Password is incorrect', 400));
      return;
    }
    next(new Err('User does not exist', 400));
  }
);

const logout = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    res.cookie('jwt', 'loggedOut', {
      expires: new Date(Date.now() + 1 * 1000),
      httpOnly: true,
    });
    ResponseGenerator(res, 200, {});
  }
);

const protect = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    let token;
    // getting the token if it exist in the request
    if (req.headers.authorization?.startsWith('Bearer') === true) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.jwt != null) {
      token = req.cookies.jwt;
    }
    if (token == null) {
      next(new Err('You are not logged in! Please log in to get access.', 401));
      return;
    }
    // validate the token with the JWT validator
    const { Jwt } = verifyJWTToken(token);
    // chceh if user exist
    const user = await User.findById({ _id: Jwt.id });

    if (user == null) {
      next(new Err('The user belonging to the token does not exist ', 401));
      return;
    }
    // if user changed the the password after the jwt was issued
    const isPasswordUpdated: boolean =
      await User.schema.methods.changedPasswordAfter(
        Jwt.iat,
        user.passwordChangedAT
      );

    if (isPasswordUpdated) {
      next(new Err('User changed the password. please login again', 401));
      return;
    }

    // grant the user access to the private route
    req.user = user;
    req.id = Jwt.id;
    next();
  }
);

// const restrictTo: (
//   role: Roles
// ) => (
//   req: Request<any, any, Record<string, any>>,
//   res: Response<any, Record<string, any>>,
//   next: NextFunction
// ) => void = (role: Roles) =>
//   CatchAsync(async (req: Request, res: Response, next: NextFunction) => {
//     // gwt the user details from the request
//     const { user } = req;
//     // check if the user have the required role for the access
//     // throw an error if conditions for the role does not satisfies
//     if (user.role !== role) {
//       next(new Err('You do not have permission to perform this action', 403));
//       return;
//     }
//     // give the user access
//     next();
//   });

const Auth = {
  register,
  login,
  protect,
  forgotPassword,
  resetPassword,
  currentPasswordChange,
  logout,
  updatePassword,
};

export default Auth;
