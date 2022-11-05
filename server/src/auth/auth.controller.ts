import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { JwtPayload } from './strategy/accesstoken.strategy';
import { JwtRefreshPayload } from './strategy/refreshToken.strategy';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signUpLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(authDto);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signInLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(authDto);
  }

  @UseGuards(AuthGuard('jwt'))
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request) {
    const user = req.user as JwtPayload;
    return this.authService.logout(user.sub);
  }

  @UseGuards(AuthGuard('jwt-refresh'))
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(@Req() req: Request) {
    console.log('req.user: ', req.user);
    const user = req.user as JwtRefreshPayload;
    return this.authService.refreshToken(user.sub, user.refreshToken);
  }
}
