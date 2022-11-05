import { ForbiddenException, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class RefreshTokenGuard extends AuthGuard('jwt-refresh') {
  constructor() {
    super();
  }

  handleRequest(err, user, info) {
    if (err || !user) {
      if (info.name === 'TokenExpiredError') {
        throw new ForbiddenException('TokenExpiredError');
      }
      throw err || new ForbiddenException('Unauthorized');
    }
    return user;
  }

  canActivate(context) {
    return super.canActivate(context);
  }
}
