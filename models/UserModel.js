import mongoose from "mongoose";
import validator from "validator";
import bcrypt from "bcryptjs";

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Please provide username"],
      trim: true,
      minlength: 3,
      maxlength: 40,
      index: true,
    },
    email: {
      type: String,
      required: [true, "Please provide email"],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, "please provide a valid email"],
      minlength: 3,
      maxlength: 100,
      index: true,
    },
    password: {
      type: String,
      required: [true, "please provide a password"],
      minlength: 4,
      select: false,
    },
    passwordconfirm: {
      type: String,
      required: [true, "please confirm password"],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: "password is not same ",
      },
    },
    isverified: {
      type: Boolean,
      default: false,
    },
    otp: {
      type: String,
      default: null,
    },
    otpexpires: {
      type: Date,
      default: null,
    },
    resetpasswordotp: {
      type: String,
      default: null,
    },
    resetpasswordotpexpires: {
      type: Date,
      default: null,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.passwordconfirm = undefined;
  next();
});

const User = mongoose.model("User", userSchema);

export default User;
