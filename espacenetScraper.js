const sgMail = require('@sendgrid/mail');
require('dotenv').config();

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const msg = {
  to: 'pankaj@bayslope.com',
  from: process.env.FROM_EMAIL,
  subject: 'Test Email from SendGrid',
  text: 'This is a test email sent from SendGrid.',
  html: '<p>This is a <strong>test email</strong> sent from SendGrid.</p>',
};

sgMail
  .send(msg)
  .then(() => console.log('Test email sent successfully'))
  .catch(error => {
    console.error('Error sending test email:', error);
    if (error.response) {
      console.error('Response:', error.response.body);
    }
  });