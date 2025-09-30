import express from "express";
import {
  forgotpassword,
  login,
  logout,
  resentotp,
  resetpassword,
  signup,
  verifyaccount,
} from "../controller/authcontroller.js";
import isAuthenticated from "../middlewares/isauthenticated.js";

const router = express.Router();

router.post("/signup", signup);
router.post("/verify", isAuthenticated, verifyaccount);
router.post("/resend-otp", isAuthenticated, resentotp);
router.post("/login", login);
router.post("/logout", logout);
router.post("/forgot-password", forgotpassword);
router.post("/reset-password", resetpassword);

export default router;
