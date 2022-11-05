import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcryptjs';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  /**
   * 로컬 회원가입
   */
  async signupLocal({ email, password }: AuthDto): Promise<Tokens> {
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const newUser = await this.prisma.user.create({
        data: {
          email,
          hashedPassword,
        },
      });

      const tokens = await this.getTokens(newUser.id, newUser.email);
      await this.updateRefreshToken(newUser.id, tokens.refreshToken);

      return tokens;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('이미 존재하는 이메일입니다.');
        } else {
          throw new ForbiddenException('회원가입에 실패했습니다.');
        }
      }
      throw new Error(error.message);
    }
  }

  /**
   * 로컬 로그인
   */
  async signinLocal({ email, password }: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Access Denied!');
    }

    const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);

    if (!isPasswordValid) {
      throw new ForbiddenException('Access Denied!');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  /**
   * 로그아웃
   * @param userId
   */
  async logout(userId: number) {
    //? Spam 요청에 대한 대비
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRefreshToken: {
          not: null,
        },
      },
      data: {
        hashedRefreshToken: null,
      },
    });
    return 'logout';
  }

  /**
   * 토큰 재발급
   * @param userId
   * @param refreshToken
   * @returns
   */
  async refreshToken(userId: number, refreshToken: string) {
    const user = await this.prisma.user.findFirst({
      where: {
        id: userId,
        hashedRefreshToken: {
          not: null, //? 로그아웃을 한 경우 hashedRefreshToken이 null이 됨
        },
      },
    });

    if (!user) {
      throw new ForbiddenException('Access Denied!');
    }

    const isRefreshTokenValid = await bcrypt.compare(
      refreshToken,
      user.hashedRefreshToken,
    );

    if (!isRefreshTokenValid) {
      throw new ForbiddenException('Access Denied!');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refreshToken);

    return tokens;
  }

  /**
   * 유저 DB에 refreshToken 저장
   * @param userId
   * @param refreshToken
   */
  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken,
      },
    });
  }

  /**
   * 토큰 발급
   * @param userId
   * @param email
   * @returns
   */
  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-secret',
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-secret',
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }
}
