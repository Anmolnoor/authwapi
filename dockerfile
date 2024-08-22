# Use an official Node.js runtime as a parent image
FROM node:22-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and yarn.lock to the working directory
COPY package.json yarn.lock ./

# Install dependencies
RUN yarn install

# Copy the rest of the application code to the working directory
COPY . .

# Build the TypeScript code
RUN yarn build

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run the app
CMD ["node", "build/server.js"]