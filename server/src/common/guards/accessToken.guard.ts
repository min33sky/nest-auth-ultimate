import { ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class AccessTokenGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  handleRequest(err, user, info) {
    if (err || !user) {
      //? 토큰 만료
      if (info.name === 'TokenExpiredError') {
        throw new ForbiddenException('TokenExpiredError');
      }
      throw err || new ForbiddenException('Unauthorized');
    }

    return user;
  }

  canActivate(context) {
    const isPublic = this.reflector.getAllAndOverride('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);

    //? Public 데코레이터가 있으면 인증을 거치지 않음
    if (isPublic) {
      return true;
    }

    return super.canActivate(context);
  }
}
