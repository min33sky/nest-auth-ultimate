import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class AppService {
  private logger: Logger;

  constructor() {
    this.logger = new Logger(AppService.name);
  }

  getHello(): string {
    this.logger.warn('getHello() called');
    return 'Hello World!';
  }
}
