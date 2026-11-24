require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require("google-auth-library");
const { Server } = require("socket.io");

const app = express();
const httpServer = http.createServer(app);
const io = new Server(httpServer);
const PORT = process.env.PORT || 8090;
const JWT_SECRET = process.env.JWT_SECRET;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 40 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, default: null },
  googleId: { type: String, default: null },
  emailVerified: { type: Boolean, default: false },
  verificationTokenHash: { type: String, default: null },
  verificationExpires: { type: Date, default: null }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  senderName: { type: String, required: true },
  text: { type: String, required: true, maxlength: 2000 },
  createdAt: { type: Date, default: Date.now }
}, { _id: true });

const roomSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 50 },
  code: { type: String, required: true, unique: true, uppercase: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  messages: [messageSchema]
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Room = mongoose.model("Room", roomSchema);

function makeToken(user) {
  return jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function publicUser(user) {
  return { id: user._id.toString(), name: user.name, email: user.email, emailVerified: user.emailVerified };
}
function authFromToken(token) {
  return jwt.verify(token, JWT_SECRET);
}
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Please log in first." });
  try {
    req.auth = authFromToken(token);
    next();
  } catch {
    return res.status(401).json({ message: "Your session expired. Please log in again." });
  }
}
function makeRoomCode() {
  return crypto.randomBytes(4).toString("hex").slice(0, 6).toUpperCase();
}
function emailTransporter() {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}
async function sendVerificationEmail(user, rawToken) {
  const transporter = emailTransporter();
  const baseUrl = process.env.CLIENT_ORIGIN || `http://localhost:${PORT}`;
  const verifyUrl = `${baseUrl}/?verify=${encodeURIComponent(rawToken)}`;
  if (!transporter) {
    if (process.env.NODE_ENV === "production") throw new Error("Email service is not configured.");
    console.log(`DEV EMAIL VERIFICATION for ${user.email}: ${verifyUrl}`);
    return verifyUrl;
  }
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: user.email,
    subject: "Verify your NexRoom email",
    text: `Hello ${user.name}, verify your NexRoom email using this link: ${verifyUrl}`,
    html: `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px"><h2>Welcome to NexRoom</h2><p>Hi ${escapeHtml(user.name)}, verify your email to activate your account.</p><p><a href="${verifyUrl}" style="display:inline-block;padding:12px 18px;background:#66e0b4;color:#10231d;text-decoration:none;border-radius:8px;font-weight:bold">Verify email</a></p><p>If you did not create this account, ignore this email.</p></div>`
  });
  return null;
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}

app.get("/api/config", (_req, res) => {
  res.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || "" });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2 || name.length > 40) return res.status(400).json({ message: "Name must be 2–40 characters." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Enter a valid email address." });
    if (password.length < 8) return res.status(400).json({ message: "Password must be at least 8 characters." });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ message: "An account with this email already exists. Try logging in." });

    const passwordHash = await bcrypt.hash(password, 12);
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const user = await User.create({
      name, email, passwordHash, emailVerified: false,
      verificationTokenHash: tokenHash,
      verificationExpires: new Date(Date.now() + 30 * 60 * 1000)
    });
    let devVerificationUrl = null;
    try {
      devVerificationUrl = await sendVerificationEmail(user, rawToken);
    } catch (mailError) {
      await User.deleteOne({ _id: user._id });
      console.error("Email send error:", mailError.message);
      return res.status(503).json({ message: "Could not send verification email. Check SMTP settings in .env and try again." });
    }
    res.status(201).json({
      message: "Account created. Check your email and verify your account before logging in.",
      devVerificationUrl
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Could not create account." });
  }
});

app.get("/api/auth/verify", async (req, res) => {
  try {
    const rawToken = String(req.query.token || "");
    if (!rawToken) return res.status(400).json({ message: "Verification link is invalid." });
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const user = await User.findOne({
      verificationTokenHash: tokenHash,
      verificationExpires: { $gt: new Date() }
    });
    if (!user) return res.status(400).json({ message: "Verification link is invalid or expired. Please register again." });
    user.emailVerified = true;
    user.verificationTokenHash = null;
    user.verificationExpires = null;
    await user.save();
    res.json({ message: "Email verified successfully. You can now log in." });
  } catch (error) {
    console.error("Verify error:", error);
    res.status(500).json({ message: "Email verification failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) return res.status(401).json({ message: "Invalid email or password." });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ message: "Invalid email or password." });
    if (!user.emailVerified) return res.status(403).json({ message: "Please verify your email first. Check your inbox." });
    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Could not log in." });
  }
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const credential = String(req.body.credential || "");
    if (!credential || !process.env.GOOGLE_CLIENT_ID) {
      return res.status(400).json({ message: "Google sign-in is not configured yet. Add GOOGLE_CLIENT_ID to .env." });
    }
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email || !payload.email_verified) {
      return res.status(401).json({ message: "Google account email could not be verified." });
    }

    const email = payload.email.toLowerCase();
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({
        name: payload.name || email.split("@")[0],
        email,
        googleId: payload.sub,
        emailVerified: true
      });
    } else {
      if (user.googleId && user.googleId !== payload.sub) {
        return res.status(409).json({ message: "This email is linked to a different Google account." });
      }
      user.googleId = payload.sub;
      user.emailVerified = true;
      await user.save();
    }
    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (error) {
    console.error("Google auth error:", error.message);
    res.status(401).json({ message: "Google sign-in failed. Check your OAuth Client ID and authorized origins." });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.auth.userId).select("_id name email emailVerified");
  if (!user) return res.status(401).json({ message: "Account not found." });
  res.json({ user: publicUser(user) });
});

app.get("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const rooms = await Room.find({ members: req.auth.userId })
      .select("name code createdAt members")
      .sort({ updatedAt: -1 }).limit(30);
    res.json({ rooms });
  } catch {
    res.status(500).json({ message: "Could not load your rooms." });
  }
});

// Socket authentication: all room actions require a valid signed-in account.
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if (!token) return next(new Error("Please log in to connect."));
    const payload = authFromToken(token);
    socket.userId = payload.userId;
    next();
  } catch {
    next(new Error("Your login session expired. Please log in again."));
  }
});

io.on("connection", async (socket) => {
  try {
    const user = await User.findById(socket.userId).select("_id name email");
    if (!user) return socket.disconnect(true);
    socket.user = user;
    console.log("Authenticated socket:", user.email);

    socket.on("create-room", async ({ roomName } = {}, callback = () => {}) => {
      try {
        const name = String(roomName || "").trim().slice(0, 50);
        if (name.length < 2) return callback({ ok: false, message: "Room name must be at least 2 characters." });
        let code;
        let exists = true;
        while (exists) {
          code = makeRoomCode();
          exists = await Room.exists({ code });
        }
        const room = await Room.create({
          name, code, createdBy: user._id, members: [user._id]
        });
        socket.join(code);
        socket.data.roomCode = code;
        const members = [{ id: user._id.toString(), name: user.name }];
        callback({ ok: true, roomCode: code, roomName: name, members, history: [] });
        io.to(code).emit("room-members", members);
        io.to(code).emit("system-message", { text: `${user.name} created this room`, time: new Date().toISOString() });
      } catch (error) {
        console.error("Create room error:", error);
        callback({ ok: false, message: "Could not create room. Please try again." });
      }
    });

    socket.on("join-room", async ({ roomCode } = {}, callback = () => {}) => {
      try {
        const code = String(roomCode || "").trim().toUpperCase();
        if (!/^[A-F0-9]{6}$/.test(code)) return callback({ ok: false, message: "Enter a valid 6-character room code." });
        const room = await Room.findOne({ code });
        if (!room) return callback({ ok: false, message: "Room not found. Create the room first or check the code." });

        if (socket.data.roomCode && socket.data.roomCode !== code) socket.leave(socket.data.roomCode);
        await Room.updateOne({ _id: room._id }, { $addToSet: { members: user._id } });
        socket.join(code);
        socket.data.roomCode = code;

        const updatedRoom = await Room.findById(room._id).populate("members", "name");
        const members = updatedRoom.members.map(member => ({ id: member._id.toString(), name: member.name }));
        const history = updatedRoom.messages.slice(-100).map(message => ({
          id: message._id.toString(), userId: message.sender.toString(),
          userName: message.senderName, text: message.text, time: message.createdAt
        }));
        callback({ ok: true, roomCode: code, roomName: room.name, members, history });
        io.to(code).emit("room-members", members);
        io.to(code).emit("system-message", { text: `${user.name} joined the room`, time: new Date().toISOString() });
      } catch (error) {
        console.error("Join room error:", error);
        callback({ ok: false, message: "Could not join room. Please try again." });
      }
    });

    socket.on("send-message", async ({ text } = {}) => {
      try {
        const code = socket.data.roomCode;
        const messageText = String(text || "").trim().slice(0, 2000);
        if (!code || !messageText) return;
        const room = await Room.findOne({ code, members: user._id });
        if (!room) return;
        const message = {
          sender: user._id, senderName: user.name, text: messageText, createdAt: new Date()
        };
        room.messages.push(message);
        // Keep the most recent 500 messages per room in this demo.
        if (room.messages.length > 500) room.messages.splice(0, room.messages.length - 500);
        await room.save();
        const saved = room.messages[room.messages.length - 1];
        io.to(code).emit("new-message", {
          id: saved._id.toString(), userId: user._id.toString(),
          userName: user.name, text: saved.text, time: saved.createdAt
        });
      } catch (error) {
        console.error("Send message error:", error);
      }
    });

    socket.on("leave-room", () => {
      const code = socket.data.roomCode;
      if (code) socket.leave(code);
      delete socket.data.roomCode;
    });

    socket.on("disconnect", () => {
      console.log("Socket disconnected:", user.email);
    });
  } catch (error) {
    console.error("Socket setup error:", error);
    socket.disconnect(true);
  }
});

async function start() {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error("Set JWT_SECRET in your .env file (minimum 32 characters).");
    process.exit(1);
  }
  if (!process.env.MONGODB_URI) {
    console.error("Set MONGODB_URI in your .env file.");
    process.exit(1);
  }
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected");
    httpServer.listen(PORT, () => console.log(`NexRoom 2.0 running at http://localhost:${PORT}`));
  } catch (error) {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  }
}
start();
