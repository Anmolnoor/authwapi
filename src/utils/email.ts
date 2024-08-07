import nodemailer from 'nodemailer';
import { env } from 'process';

interface Options {
  email: string;
  subject: string;
  msg: string;
}

const sendMail = async ({ email, msg, subject }: Options): Promise<void> => {
  // create a transporter
  // this is a service that send email like gmail...

  const transporter = nodemailer.createTransport({
    host: env.EMAIL_HOST,
    port: Number(env.EMAIL_PORT),
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
    // ACTIVE IN GMAIL "LESS SECURE APP" OPTION
  });
  // define the email options
  const mailOptions = {
    from: 'Dynamic Nexus Solutions',
    to: email,
    subject: subject,
    text: msg,
  };
  //  send the email with node mailer
  await transporter.sendMail(mailOptions);
};

export default sendMail;
