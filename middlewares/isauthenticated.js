import User from '../models/UserModel.js';
import catchAsync from '../utils/catchAsync.js';
import jwt from 'jsonwebtoken';

const isAuthenticated = catchAsync(async (req, res, next) => {
    // we will check in token in cookie 
    const token = (req.cookies && req.cookies.token) || req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: "Not authorized to login" });
    }
    let decode;
    try {
        decode = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
    const currentuser = await User.findById(decode.id);
    if (!currentuser) {
        return res.status(401).json({ message: "the user belonging to this token does not exist" });
    }
    req.user = currentuser;
    next();
});

export default isAuthenticated;