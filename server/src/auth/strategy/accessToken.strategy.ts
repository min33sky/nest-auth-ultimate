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
        AccessTokenStrategy.extractJWT, //? 쿠키에서 토큰 추출
        ExtractJwt.fromAuthHeaderAsBearerToken(), //? 헤더에서 토큰 추출
      ]),
      secretOrKey: 'at-secret',
      ignoreExpiration: false, //? false 설정 시 Passport에 검증을 위임
    });
  }

  private static extractJWT(req: Request): string | null {
    if (req.cookies && 'access_token' in req.cookies) {
      return req.cookies.access_token;
    }
    return null;
  }

  //* validate() 메서드는 토큰 검증이 성공하면 호출됨
  async validate(payload: JwtPayload) {
    return payload; //? 이 payload는 req.user에 저장됨
  }
}
