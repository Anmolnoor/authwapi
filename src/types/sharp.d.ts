declare module 'sharp' {
  interface Sharp {
    resize(width?: number, height?: number, options?: any): Sharp;
    toBuffer(): Promise<Buffer>;
    toFile(path: string): Promise<void>;
    jpeg(options?: any): Sharp;
    png(options?: any): Sharp;
    toFormat(format: string, options?: any): Sharp;
  }

  function sharp(input?: string | Buffer): Sharp;
  export = sharp;
}
