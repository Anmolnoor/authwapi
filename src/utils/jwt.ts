import { Response } from 'express';
import { decode, JwtPayload, sign, SignOptions, verify } from 'jsonwebtoken';
import { ID } from '@/types';
const secret = process.env.JWT_SECRET ?? 'this_is_my_Strong_secret';
const expiresInEnv = process.env.JWT_EXPIRES_IN;
const options: SignOptions = {
  expiresIn:
    (expiresInEnv && !Number.isNaN(Number(expiresInEnv))
      ? Number(expiresInEnv)
      : (expiresInEnv as unknown as SignOptions['expiresIn'])) || '30d',
};

interface Payload {
  id: ID;
  service?: string; // Add service identifier
  permissions?: string[]; // Add permissions array
}

const createJWTToken = (
  id: ID,
  service?: string,
  permissions?: string[]
): string => {
  const payload: Payload = {
    id,
    service,
    permissions,
  };
  const token = sign(payload, secret, options);
  return token;
};

const verifyJWTToken = (
  token: string
): {
  id: ID;
  Jwt: JwtPayload;
  service?: string;
  permissions?: string[];
} => {
  const verified = verify(token, secret);
  const { id, service, permissions } = verified as Payload;
  const decoded = decode(token);
  return { id, Jwt: decoded as JwtPayload, service, permissions };
};

// New function for service-specific token validation
const validateServiceToken = (
  token: string,
  expectedService?: string
): boolean => {
  try {
    const verified = verify(token, secret) as Payload;
    if (
      expectedService &&
      verified.service &&
      verified.service !== expectedService
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
};

const maxAge = 30 * 24 * 60 * 60 * 1000;
const createTokenwithCookie = (
  id: ID,
  res: Response,
  service?: string,
  permissions?: string[]
): string => {
  const token = createJWTToken(id, service, permissions);
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
  return token;
};

export {
  createJWTToken,
  verifyJWTToken,
  createTokenwithCookie,
  validateServiceToken,
};
