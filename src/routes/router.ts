import { ResponseGenerator } from '../utils/helper';
import express from 'express';

const route = express.Router();

route.get('/', (_req, res, next) => {
  try {
    ResponseGenerator(res, 200, 'Welcome to the API');
  } catch (error) {
    next(error);
  }
});

export default route;
