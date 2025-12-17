# Build stage
FROM node:20-slim AS builder
WORKDIR /usr/src/app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# First, copy only package files
COPY package.json yarn.lock ./

# Clean install of dependencies
RUN yarn install --frozen-lockfile

# Create types directory
RUN mkdir -p @types

# Create a proper type declaration for sharp
RUN echo 'declare module "sharp" {\n\
  interface Sharp {\n\
    resize(width?: number, height?: number): Sharp;\n\
    toBuffer(): Promise<Buffer>;\n\
    toFile(path: string): Promise<void>;\n\
  }\n\
  function sharp(input?: string | Buffer): Sharp;\n\
  export = sharp;\n\
}' > @types/sharp.d.ts

# Copy source and config
COPY tsconfig.json ./
COPY src ./src

# Update tsconfig to include custom types
RUN echo '{\n\
  "compilerOptions": {\n\
    "target": "es2017",\n\
    "module": "commonjs",\n\
    "lib": ["es2017"],\n\
    "outDir": "./build",\n\
    "rootDir": "./src",\n\
    "strict": true,\n\
    "esModuleInterop": true,\n\
    "skipLibCheck": true,\n\
    "forceConsistentCasingInFileNames": true,\n\
    "typeRoots": ["./node_modules/@types", "./@types"]\n\
  },\n\
  "include": ["src/**/*", "@types/**/*"],\n\
  "exclude": ["node_modules"]\n\
}' > tsconfig.json

# Build
RUN yarn build

# Production stage
FROM node:20-slim AS production
WORKDIR /usr/src/app

# Copy built files and package files
COPY --from=builder /usr/src/app/build ./build
COPY package.json yarn.lock ./

# Install only production dependencies
RUN yarn install --frozen-lockfile --production

# Install sharp runtime dependencies
RUN apt-get update && apt-get install -y \
    libvips \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000
CMD ["yarn", "start"]