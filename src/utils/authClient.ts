import { verify, decode, JwtPayload, sign } from 'jsonwebtoken';

interface AuthConfig {
  jwtSecret: string;
  serviceName: string;
}

interface UserInfo {
  id: string;
  email?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  service?: string;
  permissions?: string[];
}

interface TokenValidationResponse {
  valid: boolean;
  user?: UserInfo;
  message?: string;
}

interface JwtPayloadWithUser extends JwtPayload {
  id: string;
  email?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  service?: string;
  permissions?: string[];
}

class AuthClient {
  private readonly config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
  }

  /**
   * Validate JWT token locally (no HTTP call)
   */
  validateToken(token: string): TokenValidationResponse {
    try {
      const verified = verify(
        token,
        this.config.jwtSecret
      ) as JwtPayloadWithUser;
      const decoded = decode(token) as JwtPayload;

      // Check if token is expired
      if (decoded.exp && Date.now() >= decoded.exp * 1000) {
        return {
          valid: false,
          message: 'Token expired',
        };
      }

      // Optional: Validate service-specific tokens
      if (verified.service && verified.service !== this.config.serviceName) {
        return {
          valid: false,
          message: 'Token not valid for this service',
        };
      }

      return {
        valid: true,
        user: {
          id: verified.id,
          email: verified.email,
          username: verified.username,
          firstName: verified.firstName,
          lastName: verified.lastName,
          service: verified.service,
          permissions: verified.permissions,
        },
      };
    } catch (error) {
      return {
        valid: false,
        message: 'Invalid token',
      };
    }
  }

  /**
   * Middleware for Express.js applications
   */
  createAuthMiddleware() {
    return (req: any, res: any, next: any): void => {
      const token =
        req.headers.authorization?.split(' ')[1] || req.cookies?.jwt;

      if (!token) {
        res.status(401).json({ message: 'No token provided' });
        return;
      }

      const validation = this.validateToken(token);

      if (!validation.valid) {
        res
          .status(401)
          .json({ message: validation.message || 'Invalid token' });
        return;
      }

      req.user = validation.user;
      next();
    };
  }

  /**
   * Create a JWT token locally
   */
  createToken(
    userId: string,
    service?: string,
    permissions?: string[]
  ): string {
    return sign(
      {
        id: userId,
        service: service || this.config.serviceName,
        permissions,
      },
      this.config.jwtSecret,
      { expiresIn: '30d' }
    );
  }
}

export {
  AuthClient,
  type AuthConfig,
  type UserInfo,
  type TokenValidationResponse,
  type JwtPayloadWithUser,
};
