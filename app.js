const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const passport = require("passport");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors({
  origin: 'http://localhost:3000', // Your React app's origin
  credentials: true, 
}));
app.use(cookieParser());
app.use(morgan("tiny"));

// Session management for passport
app.use(require("express-session")({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true,
}));

require("./auth"); // Passport strategy initialization
const User = require("./models/user");
const sendemail = require("./models/email"); // Assume this is a utility for sending emails

// Import routes
const userRoutes = require("./routes/user");

// Passport middlewares
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection URL
const url = "mongodb://localhost:27017/user"; // Local MongoDB connection

// COOP and COEP headers
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
  next();
});

// Connect to MongoDB
mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

// Routes middleware
app.use("/api", userRoutes);

// Serve static views
app.use(express.static("public")); // Serve static files if needed

// Utility function to check if user is logged in
function isLoggedIn(req, res, next) {
  if (req.user) {
    next();
  } else {
    return res.redirect("/signin");
  }
}

// Routes
app.get("/", (req, res) => {
  if (req.cookies.token) {
    // Redirect signed-in users to the dashboard
    res.redirect("/dashboard");
  } else {
    res.render("home");
  }
});

app.get("/dashboard", isLoggedIn, (req, res) => {
  res.render("dashboard");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

// Signup route with validations
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Server-side validation for name
    const nameRegexp = /^[a-zA-Z ]+$/;
    if (!nameRegexp.test(name)) {
      return res.status(400).send("Name must contain only alphabets and spaces.");
    }

    // Server-side validation for password
    const passwordRegexp =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegexp.test(password)) {
      return res.status(400).send("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.");
    }

    const user = new User({
      name,
      email,
      password,
    });

    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error registering user");
  }
});

// Google authentication routes
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get("/auth/google/callback", 
  passport.authenticate("google", {
    failureRedirect: "/auth/google/failure",
  }), 
  (req, res) => {
    // Successful authentication, redirect to protected route
    res.redirect("/auth/google/protected");
  }
);

app.get("/auth/google/failure", (req, res) => {
  res.send("Failed to authenticate with Google");
});

app.get("/auth/google/protected", isLoggedIn, (req, res) => {
  res.send("You have successfully authenticated with Google!");
});

// Email check route
app.post("/email-check", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    return res.json({ exists: !!user });
  } catch (error) {
    console.error("Error checking email:", error);
    return res.status(500).json({ exists: false });
  }
});

// Sign-in route
app.get("/signin", (req, res) => {
  res.render("signin");
});

app.post("/signin", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await user.comparePassword(req.body.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Wrong password" });
    }

    const token = await user.jwrtoken();
    const refreshToken = await user.refreshtoken();

    const options = {
      httpOnly: true,
      expires: new Date(Date.now() + 3600 * 1000), // 1 hour expiration
    };

    res.cookie("refreshToken", refreshToken, options);
    res.cookie("token", token, options);

    res.status(200).json({ message: "Signed in successfully", token, refreshToken });
  } catch (err) {
    console.error("Sign in error:", err);
    res.status(500).json({ message: "Sign in failed" });
  }
});

// Signout route
app.post("/signout", (req, res) => {
  res.clearCookie("refreshToken");
  res.clearCookie("token");
  res.status(200).json({ message: "Signed out successfully" });
});

// Forget password route
app.get("/forgetpassword", (req, res) => {
  res.render("forgetpassword");
});

app.post("/forgetpassword", async (req, res) => {
  const userExist = await User.findOne({ email: req.body.email });

  if (!userExist) {
    return res.status(400).json({ success: false, message: "E-mail does not exist" });
  }

  const resetToken = userExist.getResetPasswordToken();
  await userExist.save({ validateBeforeSave: false });

  const resetURL = `${req.protocol}://${req.get("host")}/resetpassword/${resetToken}`;
  const message = "Click the following link to reset your password: \n\n" + resetURL;

  try {
    await sendemail({
      email: userExist.email,
      subject: "Reset Password",
      message: message,
    });

    res.status(200).json({ success: true, message: "Reset password link sent to your email" });
  } catch (error) {
    userExist.resetPasswordToken = undefined;
    userExist.resetPasswordExpires = undefined;
    await userExist.save({ validateBeforeSave: false });
    return res.status(500).json({ message: "Failed to send email" });
  }
});

// Reset password routes
app.get("/resetpassword/:token", (req, res) => {
  res.render("resetpassword", { token: req.params.token });
});

app.post("/resetpassword/:token", async (req, res) => {
  try {
    const token = crypto.createHash("sha256").update(req.params.token).digest("hex");

    const userExist = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!userExist) {
      return res.status(400).json({ success: false, message: "Invalid or expired token" });
    }

    userExist.password = req.body.password;
    userExist.resetPasswordToken = undefined;
    userExist.resetPasswordExpires = undefined;
    userExist.passwordChangedAt = Date.now();
    await userExist.save();

    res.status(200).json({ success: true, message: "Password has been reset successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Internal Server Error:", err);
  res.status(500).json({ message: "Internal Server Error" });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
