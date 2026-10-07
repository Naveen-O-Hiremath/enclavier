// Sends a test e-mail with the configured SMTP settings.
//   npm run mail:test -w @enclavier/server -- you@example.com
//   docker compose ... exec server node apps/server/dist/test-mail.js you@example.com
import { loadConfig } from '../config';
import { createMailer } from '../mail';

const to = process.argv[2];
if (!to) {
  console.error('Usage: test-mail <recipient@example.com>');
  process.exit(1);
}

const config = loadConfig();
if (!config.SMTP_HOST || (config.SMTP_USER && !config.SMTP_PASS)) {
  console.error('SMTP is not fully configured: set SMTP_HOST, SMTP_USER and SMTP_PASS.');
  process.exit(1);
}

createMailer(config, console)
  .send({
    to,
    subject: 'Enclavier SMTP test',
    text: `Enclavier can send e-mail from ${config.SMTP_FROM} via ${config.SMTP_HOST}:${config.SMTP_PORT}.`,
    html: `<p>Enclavier can send e-mail from <strong>${config.SMTP_FROM.replace(/</g, '&lt;')}</strong> via ${config.SMTP_HOST}:${config.SMTP_PORT}.</p>`,
  })
  .then(() => console.log(`Test e-mail sent to ${to}. Check the inbox (and spam folder).`))
  .catch((err: Error) => {
    console.error(`Sending failed: ${err.message}`);
    process.exitCode = 1;
  });
