import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';

export type JwtPayload = {
  sub: number;
  email: string;
  iat: number;
  exp: number;
};

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        AccessTokenStrategy.extractJWT,
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      secretOrKey: 'at-secret',
      ignoreExpiration: false, // false 설정 시 Passport에 검증을 위임
    });
  }

  private static extractJWT(req: Request): string | null {
    if (req.cookies && 'access_token' in req.cookies) {
      return req.cookies.access_token;
    }
    return null;
  }

  async validate(req, payload: JwtPayload) {
    console.log('ats ------ Payload: ', payload);
    return payload; //? 이 payload는 req.user에 저장됨
  }
}
