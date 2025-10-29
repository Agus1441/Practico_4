import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>

// mock the nodemailer module
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

// mock send email function
mockedNodemailer.createTransport = jest.fn().mockReturnValue({
  sendMail: jest.fn().mockResolvedValue({ success: true }),
});

describe('Template Injection', () => {
  const OLD_ENV = process.env;
  beforeEach (() => {
    jest.resetModules();
    jest.clearAllMocks();

  });

  it('template injection in first_name create user', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: '<%= 7*7 %>',
      last_name: 'Last',
      username: 'username',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
    .mockReturnValueOnce(selectChain as any)
    .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);


    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith(expect.objectContaining({
      html: expect.stringContaining('&lt;')}));
  }
  );

  it('template injection in last_name create user', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: '<%= 7*7 %>',
      username: 'username',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
    .mockReturnValueOnce(selectChain as any)
    .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);


    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith(expect.objectContaining({
      html: expect.stringContaining('7*7')}));
    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith(expect.objectContaining({
      html: expect.stringContaining('&lt;')}));
  }
  );

});