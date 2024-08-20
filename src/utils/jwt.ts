import { Response } from 'express';
import { decode, JwtPayload, sign, verify } from 'jsonwebtoken';
import { ID } from 'types/model.type';
const secret = process.env.JWT_SECRET ?? 'this_is_my_Strong_secret';
const options = {
  expiresIn: process.env.JWT_EXPIRES_IN ?? '30d',
};

interface Payload {
  id: ID;
}

const createJWTToken = (id: ID): string => {
  const payload: Payload = {
    id,
  };
  const token = sign(payload, secret, options);
  return token;
};

const verifyJWTToken = (
  token: string
): {
  id: ID;
  Jwt: JwtPayload;
} => {
  const verified = verify(token, secret);
  const { id } = verified as Payload;
  const decoded = decode(token);
  return { id, Jwt: decoded as JwtPayload };
};
const maxAge = 30 * 24 * 60 * 60 * 1000;
const createTokenwithCookie = (id: ID, res: Response): void => {
  const token = createJWTToken(id);
  const cookieOptions = {
    expires: new Date(Date.now() + maxAge),
    httpOnly: true,
    maxAge,
    path: '/',
    sameSite: 'strict' as const,
    secure: process.env.NODE_ENV === 'production',
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);
};

export { createJWTToken, verifyJWTToken, createTokenwithCookie };
