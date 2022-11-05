import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtRefreshPayload } from 'src/auth/strategy/refreshToken.strategy';

export const CurrentUser = createParamDecorator(
  (data: keyof JwtRefreshPayload | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();
    const user = request.user as JwtRefreshPayload;
    return data ? user && user[data] : user;
  },
);
