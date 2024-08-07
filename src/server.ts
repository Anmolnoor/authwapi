import app from './app';
import Logger from './utils/logger';
import mongoose from 'mongoose';

let server: any;

// ---- handling uncaught exceptions ----
process.on('uncaughtException', (err: Error) => {
  Logger.error(
    '🔥🔥🔥 Uncaught Exception!!! 🔥🔥🔥 Shutting Down The Server ...'
  );
  Logger.error(`Name: ${err.name}`);
  Logger.error(`Message: ${err.message}`);
  Logger.error(`Stack: ${err.stack}`);

  // Attempt to close the server gracefully
  server.close(() => {
    Logger.info('Server closed gracefully.');
    process.exit(1); // Exit with a failure code
  });

  // Forcefully shut down the server after a timeout if it doesn't close gracefully
  setTimeout(() => {
    Logger.error('Forcing server shutdown due to uncaught exception.');
    process.exit(1);
  }, 10000).unref(); // 10 seconds timeout
});

// ---- setting strictQuery to false ----
mongoose.set('strictQuery', false);

const port = process.env.PORT ?? 8000;

const startServer = async () => {
  try {
    // Validate environment variables
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('DATABASE_URL is not defined');
    }

    // Connect to the database
    await mongoose.connect(databaseUrl);
    Logger.info('DB is Connected!!');

    // Start the server
    server = app.listen(port, () => {
      Logger.info(
        `App is running in ${
          process.env.NODE_ENV ?? '{Not Defined environment}'
        } mode | Server is running on Port : ${port} `
      );
    });

    // Graceful shutdown
    const gracefulShutdown = () => {
      Logger.info('Shutting down gracefully...');
      server.close(() => {
        Logger.info('Server closed.');
        mongoose.connection.close(false);
        Logger.info('MongoDb connection closed.');
        process.exit(0); // Exit with a success code
      });

      // Force shutdown after a timeout
      setTimeout(() => {
        Logger.error('Forcing shutdown due to timeout.');
        process.exit(1);
      }, 10000).unref(); // 10 seconds timeout
    };

    process.on('SIGTERM', gracefulShutdown);
    process.on('SIGINT', gracefulShutdown);
  } catch (error) {
    Logger.error('Failed to start the server:', error);
    process.exit(1); // Exit with a failure code
  }
};

startServer();

// ---- handling unhandled rejections ----
process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  Logger.error(
    '🔥🔥🔥  Unhandled Rejection!!! 🔥🔥🔥 Shutting Down The Server ...'
  );
  Logger.error('Reason:', reason);
  Logger.error('Promise:', promise);

  server.close(() => {
    Logger.info('Server closed gracefully.');
    process.exit(1); // Exit with a failure code
  });

  // Forcefully shut down the server after a timeout if it doesn't close gracefully
  setTimeout(() => {
    Logger.error('Forcing server shutdown due to unhandled rejection.');
    process.exit(1);
  }, 10000).unref(); // 10 seconds timeout
});

export default server;
