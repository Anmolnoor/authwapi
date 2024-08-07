import mongoose from 'mongoose';
import app from '../src/app';
import Logger from '../src/utils/logger';
import startServer from '../src/server'; // Assuming you export startServer for testing

jest.mock('mongoose');
jest.mock('../src/app');
jest.mock('../src/utils/logger');
describe('startServer', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeAll(() => {
    originalEnv = process.env;
  });

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('should start the server successfully', async () => {
    process.env.DATABASE_URL = 'mongodb://localhost:27017/testdb';
    (mongoose.connect as jest.Mock).mockResolvedValueOnce({});
    const listenMock = jest.fn((port, callback) => callback());
    (app.listen as jest.Mock).mockImplementationOnce(listenMock);

    await startServer();

    expect(mongoose.connect).toHaveBeenCalledWith(
      'mongodb://localhost:27017/testdb'
    );
    expect(listenMock).toHaveBeenCalledWith(8000, expect.any(Function));
    expect(Logger.info).toHaveBeenCalledWith('DB is Connected!!');
    expect(Logger.info).toHaveBeenCalledWith(
      expect.stringContaining('App is running')
    );
  });

  it('should throw an error if DATABASE_URL is not defined', async () => {
    process.env.DATABASE_URL = undefined;

    await startServer();

    expect(Logger.error).toHaveBeenCalledWith(
      'Failed to start the server:',
      expect.any(Error)
    );
    expect(process.exit).toHaveBeenCalledWith(1);
  });

  it('should handle database connection failure', async () => {
    process.env.DATABASE_URL = 'mongodb://localhost:27017/testdb';
    const error = new Error('Connection failed');
    (mongoose.connect as jest.Mock).mockRejectedValueOnce(error);

    await startServer();

    expect(mongoose.connect).toHaveBeenCalledWith(
      'mongodb://localhost:27017/testdb'
    );
    expect(Logger.error).toHaveBeenCalledWith(
      'Failed to start the server:',
      error
    );
    expect(process.exit).toHaveBeenCalledWith(1);
  });
});
