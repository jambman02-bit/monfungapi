// ------------------------
// ✅ Dependencies
// ------------------------
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
const dotenv = require("dotenv");

// ------------------------
// ✅ Initialize Environment
// ------------------------
dotenv.config();

// ------------------------
// ✅ Firebase Admin SDK
// ------------------------
const serviceAccount = require("/etc/secrets/firebase-key.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://hackerpdf-f6074-default-rtdb.firebaseio.com",
});

const db = admin.database();

// ------------------------
// ✅ Express App Setup
// ------------------------
const app = express();
app.use(cors());
app.use(bodyParser.json());

// ------------------------
// ✅ Nodemailer Transporter
// ------------------------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ------------------------
// ✅ Helper Functions
// ------------------------
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000);
}

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: process.env.FROM_EMAIL,
      to,
      subject,
      html,
    });
    return true;
  } catch (error) {
    console.error("Email sending error:", error);
    return false;
  }
}

async function storeOTP(email, otp, purpose) {
  const expiry = Date.now() + process.env.OTP_EXPIRY_MINUTES * 60 * 1000;
  await db.ref("otps/" + email.replace(/\./g, "_")).set({
    otp,
    purpose,
    expiry,
  });
}

async function verifyOTP(email, otp, purpose) {
  const snapshot = await db.ref("otps/" + email.replace(/\./g, "_")).once("value");
  const data = snapshot.val();

  if (!data) return { success: false, message: "No OTP found" };
  if (data.purpose !== purpose) return { success: false, message: "Purpose mismatch" };
  if (Date.now() > data.expiry) return { success: false, message: "OTP expired" };
  if (data.otp != otp) return { success: false, message: "Invalid OTP" };

  await db.ref("otps/" + email.replace(/\./g, "_")).remove();
  return { success: true, message: "OTP verified successfully" };
}

// ------------------------
// ✅ Middleware: Verify API Key
// ------------------------
function verifyApiKey(req, res, next) {
  const clientKey = req.headers["x-api-key"];
  if (!clientKey) return res.status(401).json({ success: false, message: "API key missing" });
  if (clientKey !== process.env.API_KEY)
    return res.status(403).json({ success: false, message: "Invalid API key" });
  next();
}

// ------------------------
// ✅ Routes
// ------------------------
app.post("/send-verification", verifyApiKey, async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ success: false, message: "Email required" });

  const otp = generateOTP();
  const html = `
    <h2>Account Verification</h2>
    <p>Hi ${name || "User"},</p>
    <p>Your verification code is:</p>
    <h3>${otp}</h3>
    <p>This code will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.</p>
  `;

  const sent = await sendEmail(email, "Account Verification Code", html);
  if (sent) {
    await storeOTP(email, otp, "verification");
    res.json({ success: true, message: "Verification email sent" });
  } else {
    res.status(500).json({ success: false, message: "Failed to send email" });
  }
});

app.post("/send-reset", verifyApiKey, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, message: "Email required" });

  const otp = generateOTP();
  const html = `
    <h2>Password Reset</h2>
    <p>Your password reset code is:</p>
    <h3>${otp}</h3>
    <p>This code will expire in ${process.env.OTP_EXPIRY_MINUTES} minutes.</p>
  `;

  const sent = await sendEmail(email, "Password Reset Code", html);
  if (sent) {
    await storeOTP(email, otp, "reset");
    res.json({ success: true, message: "Password reset email sent" });
  } else {
    res.status(500).json({ success: false, message: "Failed to send email" });
  }
});

app.post("/verify-otp", verifyApiKey, async (req, res) => {
  const { email, otp, purpose } = req.body;
  if (!email || !otp || !purpose)
    return res.status(400).json({ success: false, message: "Email, OTP, and purpose are required" });

  const result = await verifyOTP(email, otp, purpose);
  res.json(result);
});

// ------------------------
// ✅ Start Server
// ------------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ OTP API running on port ${PORT}`));
