import { ForbiddenException, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from './accesstoken.strategy';

export type JwtRefreshPayload = JwtPayload & {
  refreshToken: string;
};

@Injectable()
export class RefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: 'rt-secret',
      ignoreExpiration: false,
      passReqToCallback: true, //? DB의 refresh token과 비교하기 위해 추가 (아래 validate 메서드에서 사용)
    });
  }

  async validate(request: Request, payload: any) {
    const refreshToken = request.get('Authorization')?.split(' ')[1];

    if (!refreshToken) throw new ForbiddenException('Refresh token malformed');

    return {
      ...payload,
      refreshToken,
    };
  }
}
