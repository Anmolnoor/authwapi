import { NextFunction, Request, Response } from 'express';
import { ResponseGenerator, CatchAsync } from '../utils/helper';
import User from '../models/user.model';
import { createTokenwithCookie, verifyJWTToken } from '../utils/jwt';
import Err from '../utils/errorHandler';
import {
  ID,
  IUser,
  permissions as permissionsEnum,
  service as services,
} from '../types/model.type';
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
      handle,
      password,
      passwordConfirm,
      image,
      firstName,
      lastName,
      phone,
      service,
    } = req.body;

    // TODO: validate the user data and throw an error if the data is not valid
    if (!service) {
      next(new Err('Service is required', 400));
      return;
    }

    if (!Object.values(services).includes(service)) {
      next(new Err('Service is not valid', 400));
      return;
    }
    // create the permissions for the user for the service
    const permissionsForService = {
      [service]: [
        permissionsEnum.create,
        permissionsEnum.read,
        permissionsEnum.update,
        permissionsEnum.delete,
        permissionsEnum.export,
        permissionsEnum.import,
        permissionsEnum.print,
        permissionsEnum.download,
        permissionsEnum.upload,
        permissionsEnum.share,
        permissionsEnum.view,
      ],
    };

    // create a new user
    const normalizedHandle =
      typeof handle === 'string'
        ? handle.toLowerCase().trim().replace(/\s+/g, '')
        : undefined;
    const user = await User.create({
      email,
      username,
      handle: normalizedHandle,
      password,
      passwordConfirm,
      image,
      firstName,
      lastName,
      phone,
      service: [service],
      permissions: permissionsForService,
    });

    // extra fetures that we wanna add to the user
    // create the token and send to the user
    const token = createTokenwithCookie(
      user.id,
      res,
      service,
      user.permissions[service]
    );
    ResponseGenerator(res, 201, { user, token });
  }
);

const login = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // get the user details from the req
    const { username, password, service } = req.body;
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
        // choose active service for token
        const userServices = Array.isArray(user.service)
          ? user.service
          : [user.service];
        const requestedService = service as string | undefined;
        const activeService =
          requestedService && userServices.includes(requestedService)
            ? requestedService
            : userServices[0];
        // create the token and send to the user
        const token = createTokenwithCookie(
          user._id,
          res,
          activeService,
          user.permissions[activeService]
        );
        return ResponseGenerator(res, 201, {
          user,
          token,
        });
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
        const token = createTokenwithCookie(id, res);
        ResponseGenerator(res, 201, { token });
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
        const userServices = Array.isArray(user.service)
          ? user.service
          : [user.service];
        const activeService = userServices[0];
        const token = createTokenwithCookie(
          user.id,
          res,
          activeService,
          user.permissions[activeService]
        );
        ResponseGenerator(res, 201, { user, token });
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
        const token = createTokenwithCookie(
          id,
          res,
          user.service,
          user.permissions[user.service]
        );
        ResponseGenerator(res, 201, { token });
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

// New method for token validation (for other services)
const validateToken = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { token, service } = req.body;

    if (!token) {
      next(new Err('Token is required', 400));
      return;
    }

    try {
      const { id, service: tokenService, permissions } = verifyJWTToken(token);
      const user = await User.findById({ _id: id });

      if (!user) {
        next(new Err('User not found', 404));
        return;
      }

      // Check if password was changed after token was issued
      const isPasswordUpdated: boolean =
        await User.schema.methods.changedPasswordAfter(
          verifyJWTToken(token).Jwt.iat,
          user.passwordChangedAt
        );

      if (isPasswordUpdated) {
        next(new Err('Token is invalid - password changed', 401));
        return;
      }

      // Optional service validation
      if (service && tokenService && service !== tokenService) {
        next(new Err('Token not valid for this service', 403));
        return;
      }

      ResponseGenerator(res, 200, {
        valid: true,
        user: {
          id: user._id,
          email: user.email,
          username: user.username,
          handle: user.handle,
          firstName: user.firstName,
          lastName: user.lastName,
          service: tokenService,
          permissions,
        },
      });
    } catch (error) {
      ResponseGenerator(res, 401, {
        valid: false,
        message: 'Invalid token',
      });
    }
  }
);

// New method for service-specific login
const serviceLogin = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { username, password, service, permissions } = req.body;

    if (!username || !password || !service) {
      next(new Err('Username, password, and service are required', 400));
      return;
    }

    const user = await User.findOne({
      $or: [{ email: username }, { username }],
    });

    if (!user) {
      return loginFailed(res);
    }

    const isAuthorized: boolean = await User.schema.methods.correctPassword(
      user.password,
      password
    );

    if (!isAuthorized) {
      return loginFailed(res);
    }

    // Create service-specific token
    const token = createTokenwithCookie(user._id, res, service, permissions);

    ResponseGenerator(res, 200, {
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        handle: user.handle,
        firstName: user.firstName,
        lastName: user.lastName,
        service,
        permissions,
      },
      token,
    });
  }
);

// New method to get user info
const getUserInfo = CatchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { user } = req;

    ResponseGenerator(res, 200, {
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        handle: user.handle,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
        image: user.image,
        service: user.service,
        permissions: user.permissions,
      },
    });
  }
);

// ---- Handle availability checks (moved from user controller) ----
const validateAndCheckHandle = async (
  rawHandle: unknown,
  next: NextFunction
) => {
  if (!rawHandle || typeof rawHandle !== 'string') {
    return next(new Err('Invalid handle provided', 400));
  }

  const normalizedHandle = rawHandle.toLowerCase().trim().replace(/\s+/g, '');

  if (normalizedHandle.length < 3 || normalizedHandle.length > 30) {
    return next(new Err('Handle must be between 3 and 30 characters', 400));
  }

  if (!/^[a-z0-9_-]+$/.test(normalizedHandle)) {
    return next(
      new Err(
        'Handle can only contain letters, numbers, underscores, and hyphens',
        400
      )
    );
  }

  const reservedHandles = ['admin', 'moderator', 'support', 'help'];
  if (reservedHandles.includes(normalizedHandle)) {
    return next(new Err('This handle is reserved and cannot be used', 403));
  }

  const user = await User.findOne({
    $or: [{ username: normalizedHandle }, { handle: normalizedHandle }],
  });
  if (user !== null) {
    return next(new Err('Handle is already taken by a user', 409));
  }

  return normalizedHandle;
};

// POST /check-handle { handle }
const getHandle = CatchAsync(async (req: Request, res: Response, next) => {
  try {
    const normalizedHandle = (await validateAndCheckHandle(
      req.body.handle,
      next
    )) as string | undefined;
    if (!normalizedHandle) return;

    ResponseGenerator(res, 200, {
      msg: 'Handle is available',
      handle: normalizedHandle,
    });
  } catch (error) {
    return next(new Err('Error checking handle availability', 500));
  }
});

// GET /check-handle/:handle? or /check-handle?handle=
const getHandleGet = CatchAsync(async (req: Request, res: Response, next) => {
  try {
    const handleFromReq = (req.params.handle ||
      (req.query.handle as string)) as string | undefined;
    const normalizedHandle = (await validateAndCheckHandle(
      handleFromReq,
      next
    )) as string | undefined;
    if (!normalizedHandle) return;

    ResponseGenerator(res, 200, {
      msg: 'Handle is available',
      handle: normalizedHandle,
    });
  } catch (error) {
    return next(new Err('Error checking handle availability', 500));
  }
});

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
        user.passwordChangedAt
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
  validateToken,
  serviceLogin,
  getUserInfo,
  getHandle,
  getHandleGet,
};

export default Auth;
