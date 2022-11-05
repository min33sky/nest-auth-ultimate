import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/local/signup')
  signUpLocal(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(authDto);
  }

  @Post('/local/signin')
  signInLocal() {
    return 'sign in local';
  }

  @Post('/logout')
  logout() {
    return 'logout';
  }

  @Post('/refresh')
  refreshToken() {
    return 'refresh token';
  }
}
