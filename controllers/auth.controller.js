import bcrypt from "bcryptjs";
import { User } from "../models/user.model.js";
import { OTP } from "../models/otp.model.js";
import { sendEmail } from "../utils/sendEmail.js";

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000); // 6-digit OTP

// Send OTP
export const sendOTP = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otpCode = generateOTP();

    // Save OTP in database (overwrites any previous OTP for this email)
    await OTP.findOneAndUpdate(
      { email },
      { otp: otpCode, createdAt: new Date() },
      { upsert: true }
    );

    // Send OTP via email
    await sendEmail(email, "Password Reset OTP", `Your OTP is ${otpCode}. It expires in 5 minutes.`);

    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error sending OTP" });
  }
};

// Verify OTP
export const verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const validOtp = await OTP.findOne({ email, otp });

    if (!validOtp) return res.status(400).json({ message: "Invalid or expired OTP" });

    // Check if OTP is expired
    const now = new Date();
    if (now - validOtp.createdAt > 300000) { // 5 minutes
      await OTP.deleteOne({ email, otp }); // Delete expired OTP
      return res.status(400).json({ message: "OTP expired. Request a new one." });
    }

    res.json({ message: "OTP verified successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error verifying OTP" });
  }
};

// Reset Password
export const resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    const validOtp = await OTP.findOne({ email, otp });
    if (!validOtp) return res.status(400).json({ message: "Invalid or expired OTP" });

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await User.findOneAndUpdate({ email }, { password: hashedPassword });

    // Delete OTP after successful password reset
    await OTP.deleteOne({ email, otp });

    res.json({ message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ message: "Error resetting password" });
  }
};
