import User from "../models/UserModel.js";
import catchAsync from "../utils/catchAsync.js";
import generateotp from "../utils/generateotp.js";
import jwt from "jsonwebtoken";
import sendemail from "../utils/email.js";
import bcrypt from "bcryptjs";

const signtoken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createsendtoken = (statuscode, user, res, message) => {
  const token = signtoken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "Lax",
  };

  res.cookie("token", token, cookieOptions);
  user.password = undefined;
  user.passwordconfirm = undefined;
  user.otp = undefined;

  res
    .status(statuscode)
    .json({ message, status: "success", token, data: user });
};

const signup = catchAsync(async (req, res, next) => {
  const { email, password, passwordconfirm, username } = req.body;
  const existinguser = await User.findOne({ email });
  if (existinguser) {
    return res
      .status(400)
      .json({ message: "email with this user already exists" });
  }
  const otp = generateotp();
  const otpexpires = Date.now() + 100 * 60 * 60 * 1000; // Expires in 24 hours

  const newuser = await User.create({
    email,
    password,
    username,
    passwordconfirm,
    otp,
    otpexpires,
  });

  try {
    await sendemail({
      email: newuser.email,
      subject: "OTP for email verification",
      otp: otp,
    });
    createsendtoken(200, newuser, res, "Registration sucecssfull");
  } catch (error) {
    await User.findByIdAndDelete(newuser.id);
    return next({ message: "there is an error in signup" });
  }
});

const verifyaccount = async (req, res, next) => {
  const { otp } = req.body;
  if (!otp) return next({ message: "otp is missing" });

  //isAuthenticated req.user
  const user = req.user;
  if (user.otp !== otp) {
    return res.status(401).json({ message: "invalid otp" });
  }

  if (Date.now() > user.otpexpires) {
    return res
      .status(401)
      .json({ message: "Otp expired please get a new otp" });
  }
  user.isverified = true;
  user.otp = undefined;
  user.otpexpires = undefined;
  await user.save({ validateBeforeSave: false });
  createsendtoken(200, user, res, "email has been verified");
};

const resentotp = catchAsync(async (req, res, next) => {
  const { email } = req.user;
  if (!email) {
    return res.status(401).json({ message: "Email is required" });
  }
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(401).json({ message: "wrong email user not found" });
  }
  if (user.isverified) {
    return res.status(401).json({ message: " email is already verified" });
  }
  const newotp = generateotp();
  user.otp = newotp;
  user.otpexpires = Date.now() + 24 * 60 * 60 * 100;
  await user.save({ validateBeforeSave: false });
  try {
    await sendemail({
      email: user.email,
      subject: "Resend otp for email verification ",
      otp: newotp,
    });
    res.status(200).json({ message: "otp has been sent" });
  } catch (error) {
    user.otp = undefined;
    user.otpexpires = undefined;
    await user.save({ validateBeforeSave: false });
    res.status(500).json({ message: "Internel server error " });
  }
});

const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(401).json({ message: "Email and Password are required" });
  }
  const user = await User.findOne({ email }).select("+password");

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid email or password" });
  }
  createsendtoken(200, user, res, "Login successful");
});

const logout = catchAsync(async (req, res, next) => {
  res.cookie("token", "logdedout", {
    expires: new Date(Date.now() + 5 * 1000),
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  });
  res
    .status(200)
    .json({ success: true, message: "User logged out successfully" });
});

const forgotpassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res
      .status(401)
      .json({ message: "No user with this email is registered" });
  }
  user.resetpasswordotp = generateotp();
  user.resetpasswordotpexpires = Date.now() + 10 * 60 * 1000;
  await user.save({ validateBeforeSave: false });
  try {
    await sendemail({
      email: user.email,
      subject: "OTP for password reset",
      otp: user.resetpasswordotp,
    });
    res.status(200).json({ message: "OTP sent to email for password reset" });
  } catch (error) {
    user.resetpasswordotp = undefined;
    user.resetpasswordotpexpires = undefined;
    await user.save({ validateBeforeSave: false });
    res.status(500).json({ message: "Internal server error" });
  }
});

const resetpassword = catchAsync(async (req, res, next) => {
  const { email, otp, password, passwordconfirm } = req.body;
  const user = await User.findOne({
    email,
    resetpasswordotp: otp,
    resetpasswordotpexpires: { $gt: Date.now() },
  });
  if (!user) {
    return res
      .status(401)
      .json({ message: "user with this email not exists to reset password" });
  }
  user.password = password;
  user.passwordconfirm = passwordconfirm;
  user.resetpasswordotp = undefined;
  user.resetpasswordotpexpires = undefined;
  await user.save();
  createsendtoken(200, user, res, "password reset successfull");
});

export {
  signup,
  verifyaccount,
  resentotp,
  login,
  logout,
  forgotpassword,
  resetpassword,
};
