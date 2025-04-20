import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: Number, required: true }, // Changed String → Number
  createdAt: { type: Date, default: Date.now, expires: 300 }, // Expires in 5 mins
});

export const OTP = mongoose.model("OTP", otpSchema);
