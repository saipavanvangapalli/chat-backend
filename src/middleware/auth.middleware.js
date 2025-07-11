import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute = async (req, res, next) => {
  try {
    const token = req.cookies?.jwt; // ✅ optional chaining for safety

    if (!token) {
      return res.status(401).json({ message: "Unauthorized - No Token Provided" });
    }

    // ✅ Decode and verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.log("Error in protectRoute middleware:", error.message);
    res.status(401).json({ message: "Unauthorized - Invalid Token" });
  }
};
