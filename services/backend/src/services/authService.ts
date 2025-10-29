import crypto from 'crypto';
import nodemailer from 'nodemailer';
import db from '../db';
import { User, UserRow } from '../types/user';
import jwtUtils from '../utils/jwt';
import ejs from 'ejs';

const RESET_TTL = 1000 * 60 * 60;           // 1h
const INVITE_TTL = 1000 * 60 * 60 * 24 * 7; // 7d

class PasswordUtils {
  private static readonly SALT_LENGTH = 16;    
  private static readonly KEY_LENGTH = 64;     

  //hashear contraseña de forma segura
  static async hashPassword(password: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const salt = crypto.randomBytes(this.SALT_LENGTH);
      
      crypto.scrypt(password, salt, this.KEY_LENGTH, (err, derivedKey) => {
        if (err) reject(err);
        
        const saltHex = salt.toString('hex');
        const hashHex = derivedKey.toString('hex');
        resolve(`${saltHex}:${hashHex}`);
      });
    });
  }

  // verificar contraseña hasheada
  static async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      try {
        // formato
        const [saltHex, hashHex] = storedHash.split(':');
        if (!saltHex || !hashHex) {
          return resolve(false);
        }
        
        // convertir hex strings a buffers
        const salt = Buffer.from(saltHex, 'hex');
        const originalHash = Buffer.from(hashHex, 'hex');
        
        //hashear password recibido con mismo salt
        crypto.scrypt(password, salt, this.KEY_LENGTH, (err, derivedKey) => {
          if (err) reject(err);
          
          const isValid = crypto.timingSafeEqual(originalHash, derivedKey);
          resolve(isValid);
        });
      } catch (error) {
        resolve(false); // error en parsing = contraseña inválida
      }
    });
  }
}
//en todos las funciones ahora se guarda el hash seguro de la contraseña
class AuthService {

  static async createUser(user: User) {
    const existing = await db<UserRow>('users')
      .where({ username: user.username })
      .orWhere({ email: user.email })
      .first();
    if (existing) throw new Error('User already exists with that username or email');
    
    const hashedPassword = await PasswordUtils.hashPassword(user.password);

    // create invite token
    const invite_token = crypto.randomBytes(6).toString('hex');
    const invite_token_expires = new Date(Date.now() + INVITE_TTL);

    await db<UserRow>('users').insert({
      username: user.username,
      password: hashedPassword,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      invite_token,
      invite_token_expires,
      activated: false
    });

    // send invite email using nodemailer and local SMTP server
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const link = `${process.env.FRONTEND_URL}/activate-user?token=${invite_token}&username=${user.username}`;
   
    const template = `
      <html>
        <body>
          <h1>Hello <%= firstName %> <%= lastName %></h1>
          <p>Click <a href="<%= link %>">here</a> to activate your account.</p>
        </body>
      </html>`;

    const htmlBody = ejs.render(template, {
      firstName: user.first_name,
      lastName: user.last_name,
      link
    });
    
    await transporter.sendMail({
      from: "no-reply@test.local",   // ✅ dirección dummy válida para MailHog
      to: user.email,
      subject: 'Activate your account',
      html: htmlBody
    });
  }

  static async updateUser(user: User) {
    const existing = await db<UserRow>('users')
      .where({ id: user.id })
      .first();
    if (!existing) throw new Error('User not found');
    
    const hashedPassword = await PasswordUtils.hashPassword(user.password);
    
    await db<UserRow>('users')
      .where({ id: user.id })
      .update({
        username: user.username,
        password: hashedPassword,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name
      });
    return existing;
  }

  static async authenticate(identifier: string, password: string) {
    const isEmail = identifier.includes('@');

    const user = isEmail
      ? await db<UserRow>('users').where({ email: identifier }).andWhere('activated', true).first()
      : await db<UserRow>('users').where({ username: identifier }).andWhere('activated', true).first();

    if (!user) throw new Error('Invalid email/username or not activated');
    const isPasswordValid = await PasswordUtils.verifyPassword(password, user.password);
    if (!isPasswordValid) throw new Error('Invalid password');

    const { password: _, ...safeUser } = user;
    return safeUser;
  }

  static async sendResetPasswordEmail(email: string) {
    const user = await db<UserRow>('users')
      .where({ email })
      .andWhere('activated', true)
      .first();
    if (!user) throw new Error('No user with that email or not activated');

    const token = crypto.randomBytes(6).toString('hex');
    const expires = new Date(Date.now() + RESET_TTL);

    await db('users')
      .where({ id: user.id })
      .update({
        reset_password_token: token,
        reset_password_expires: expires
      });

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      from: "no-reply@test.local",   // ✅ mismo fix acá
      to: user.email,
      subject: 'Your password reset link',
      html: `Click <a href="${link}">here</a> to reset your password.`
    });
  }

  static async resetPassword(token: string, newPassword: string) {
    const row = await db<UserRow>('users')
      .where('reset_password_token', token)
      .andWhere('reset_password_expires', '>', new Date())
      .first();
    if (!row) throw new Error('Invalid or expired reset token');

    const hashedPassword = await PasswordUtils.hashPassword(newPassword);

    await db('users')
      .where({ id: row.id })
      .update({
        password: hashedPassword,
        reset_password_token: null,
        reset_password_expires: null
      });
  }

  static async setPassword(token: string, newPassword: string) {
    const row = await db<UserRow>('users')
      .where('invite_token', token)
      .andWhere('invite_token_expires', '>', new Date())
      .first();
    if (!row) throw new Error('Invalid or expired invite token');

  
    const hashedPassword = await PasswordUtils.hashPassword(newPassword);

    await db('users')
      .update({
        password: hashedPassword, 
        invite_token: null,
        invite_token_expires: null
      })
      .where({ id: row.id });
  }

  static generateJwt(userId: string): string {
    return jwtUtils.generateToken(userId);
  }
}

export default AuthService;