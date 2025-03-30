// src/services/logger.ts
enum LogLevel {
    DEBUG = 'DEBUG',
    INFO = 'INFO',
    WARN = 'WARN',
    ERROR = 'ERROR',
  }
  
  class Logger {
    private context: string;
  
    constructor(context: string) {
      this.context = context;
    }
  
    private log(level: LogLevel, message: string, meta?: any): void {
      const timestamp = new Date().toISOString();
      const logData = {
        timestamp,
        level,
        context: this.context,
        message,
        ...(meta && { meta }),
      };
      
      // 在生产环境中，你可能想将日志写入文件或发送到日志服务
      console.log(JSON.stringify(logData));
    }
  
    debug(message: string, meta?: any): void {
      this.log(LogLevel.DEBUG, message, meta);
    }
  
    info(message: string, meta?: any): void {
      this.log(LogLevel.INFO, message, meta);
    }
  
    warn(message: string, meta?: any): void {
      this.log(LogLevel.WARN, message, meta);
    }
  
    error(message: string, error?: Error, meta?: any): void {
      const errorMeta = error ? {
        name: error.name,
        message: error.message,
        stack: error.stack,
        ...meta,
      } : meta;
      
      this.log(LogLevel.ERROR, message, errorMeta);
    }
  }
  
  export const createLogger = (context: string): Logger => {
    return new Logger(context);
  };