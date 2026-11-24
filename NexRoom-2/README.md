# NexRoom 2.0 — MongoDB + Email Verification + Google OAuth

This is a separate upgraded version of NexRoom. It does not edit ChatNova or the earlier NexRoom folder.

## Included
- MongoDB persistence for users, rooms, room members, and chat messages.
- Email/password registration and login.
- Password hashing with bcrypt.
- Email verification links using Nodemailer SMTP.
- Google sign-in using Google Identity Services; the server verifies the Google ID token.
- JWT-protected API routes and authenticated Socket.IO connections.
- Room membership authorization on join and message send.
- Room history loaded from MongoDB.
- Same UI style, separate port 8090.

## 1. Requirements
- Node.js 18+
- MongoDB Atlas account (or local MongoDB)
- Google Cloud project and OAuth Web Client ID (for Google login)
- Gmail App Password or another SMTP provider (for verification email)

## 2. Open in VS Code
Extract this ZIP, open the `NexRoom-2` folder in VS Code, then open Terminal.

Run:
```bash
npm install
```

## 3. Configure environment variables
Copy `.env.example` to a new file named `.env`. Fill in:

### MongoDB
Create a free MongoDB Atlas cluster, create a database user, allow your IP address in Network Access, and copy the Node.js connection string into `MONGODB_URI`. Replace the username, password, and cluster host. URL-encode special characters in the database password.

### JWT
Set `JWT_SECRET` to a long random secret (at least 32 characters). Do not share or commit `.env`.

### Google OAuth
1. Open Google Cloud Console: https://console.cloud.google.com/
2. Create/select a project and configure the OAuth consent screen.
3. Create Credentials → OAuth client ID → Web application.
4. Add `http://localhost:8090` under Authorized JavaScript origins.
5. Copy the Client ID into `GOOGLE_CLIENT_ID` in `.env`.

Google sign-in will not work until this real Client ID is configured.

### Email verification
For Gmail, enable 2-Step Verification and create an App Password. Put the 16-character App Password in `SMTP_PASS`, your Gmail address in `SMTP_USER`, and use the same address in `MAIL_FROM`. Do not use your normal Gmail password.

If SMTP is not configured in development mode, the server prints a local verification URL in the terminal and also displays a local testing link after registration. This fallback is disabled in production.

## 4. Run
```bash
npm start
```
Open:
http://localhost:8090

## 5. Test
1. Register with a real email address and password of at least 8 characters.
2. Verify using the email link. Without SMTP in development, use the local verification link shown on the page or in the terminal.
3. Log in.
4. Create a room and copy its six-character code.
5. Open a second browser profile/device, register and verify another account, log in, then join using the code.
6. Send messages from both users. Refreshing the page and rejoining the room loads saved message history.

## Important
- Old NexRoom used port 8090 too. Stop the old NexRoom server before starting this upgraded server, or change `PORT` in `.env` (and update Google authorized origin if needed).
- ChatNova remains separate on port 8080.
- This is a learning/demo baseline, not a production deployment. Before public deployment add HTTPS, rate limiting, CSRF/XSS review, account recovery, email resend flow, stronger session/token storage, abuse controls, and database backups.
- Do not commit `.env` or share your database credentials, SMTP app password, Google client secrets, or JWT secret.
