const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const User = require("./models/user");
const Post = require("./models/post");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const flash = require("connect-flash");
const session = require("express-session");
const upload = require("./config/multerrconfig");
const verifyRecaptcha = require("./middlewares/recaptcha.js");
require('dotenv').config();
const app = express();
if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is not set in environment variables!");
}
const jwtSecret = process.env.JWT_SECRET;
const { sendVerificationEmail, sendWelcomeEmail,sendResetingVerificationEmail,sendpasswordchangetemplate } = require("./middlewares/email.js");

app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

app.use(
  session({
    secret: jwtSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 5000 },
  })
);
app.use(flash());

app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success");
  res.locals.error_msg = req.flash("error");
  next();
});

function isLoggedIn(req, res, next) {
  if (!req.cookies.token) {
    req.flash("error", "Please log in first");
    return res.redirect("/login");
  }

  try {
    let data = jwt.verify(req.cookies.token, jwtSecret);
    req.user = data;

    if (!req.user.isVerified) {
      req.flash("error", "Please verify your email first.");
      return res.redirect("/verify-otp");
    }

    next();
  } catch (err) {
    res.clearCookie("token");
    req.flash("error", "Session expired, please log in again");
    res.redirect("/login");
  }
}

function isVerificationPending(req, res, next) {
  if (!req.cookies.token) {
    req.flash("error", "Please log in first");
    return res.redirect("/login");
  }

  try {
    let data = jwt.verify(req.cookies.token, jwtSecret);
    req.user = data;

    if (req.user.isVerified) {
      return res.redirect("/profile");
    }

    next();
  } catch (err) {
    res.clearCookie("token");
    req.flash("error", "Session expired, please log in again");
    res.redirect("/login");
  }
}

app.get("/", (req, res) => {
  res.render("index", {
    name: "",
    username: "",
    email: "",
    age: "",
    success_msg: req.flash("success"),
    error_msg: req.flash("error"),
  });
});

app.get("/login", (req, res) => {
  if (req.cookies.token) {
    try {
      jwt.verify(req.cookies.token, jwtSecret);
      req.flash("success", "You are already logged in!");
      return res.redirect("/profile");
    } catch (err) {
      res.clearCookie("token");
    }
  }
  res.render("login");
});

app.get("/profile", isLoggedIn, async (req, res) => {
  try {
    let user = await User.findOne({ email: req.user.email }).populate("posts");
    res.render("profile", { user });
  } catch (err) {
    console.error("❌ Error fetching user:", err);
    req.flash("error", "Something went wrong. Please try again.");
    res.redirect("/login");
  }
});

app.post("/post", isLoggedIn, async function (req, res) {
  let { postContent } = req.body;

  if (!postContent.trim()) {
    req.flash("error", "Post content cannot be empty.");
    return res.redirect("/profile");
  }

  try {
    if (!req.user || !req.user.email) {
      req.flash("error", "User not found. Please log in again.");
      return res.redirect("/login");
    }

    let user = await User.findOne({ email: req.user.email });
    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/profile");
    }

    let newPost = await Post.create({
      title: `@${user.name}`,
      content: postContent,
      user: user._id,
    });

    user.posts.push(newPost._id);
    await user.save();

    req.flash("success", "Post created successfully!");
    res.redirect("/profile");
  } catch (err) {
    console.error("❌ Error creating post:", err);
    req.flash("error", "Something went wrong.");
    res.redirect("/profile");
  }
});

app.get("/like/:id", isLoggedIn, async (req, res) => {
  try {
    let post = await Post.findById(req.params.id);
    if (!post) {
      req.flash("error", "Post not found.");
      return res.redirect("/profile");
    }

    if (!post.likes) {
      post.likes = [];
    }

    if (!post.likes.includes(req.user.userid)) {
      post.likes.push(req.user.userid);
      await post.save();
      req.flash("success", "Post liked!");
    } else {
      post.likes.splice(req.user.userid);
      await post.save();
      req.flash("success", "Post Disliked!");
    }
  } catch (err) {
    console.error("❌ Error liking post:", err);
    req.flash("error", "Something went wrong.");
  }
  res.redirect("/profile");
});

app.get("/edit/:id", isLoggedIn, async (req, res) => {
  try {
    let post = await Post.findById(req.params.id);
    if (!post) {
      req.flash("error", "Post not found.");
      return res.redirect("/profile");
    }
    res.render("edit", { post });
  } catch (err) {
    console.error("❌ Error fetching post for edit:", err);
    req.flash("error", "Something went wrong.");
    res.redirect("/profile");
  }
});

app.post("/update/:id", isLoggedIn, async (req, res) => {
  let { content } = req.body;

  try {
    let post = await Post.findById(req.params.id);
    if (!post) {
      req.flash("error", "Post not found.");
      return res.redirect("/profile");
    }

    post.content = content;
    await post.save();

    req.flash("success", "Post updated successfully!");
  } catch (err) {
    console.error("❌ Error updating post:", err);
    req.flash("error", "Something went wrong.");
  }

  res.redirect("/profile");
});

app.post("/login", verifyRecaptcha, async (req, res) => {
  let { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      req.flash("error", "Invalid email or password");
      return res.redirect("/login");
    }

    let token = jwt.sign(
      { email, userid: user._id, isVerified: user.isVerified },
      jwtSecret,
      { expiresIn: "1h" }
    );
    res.cookie("token", token, { httpOnly: true });

    req.flash("success", "Login successful!");
    res.redirect("/profile");
  } catch (err) {
    console.error("❌ Error during login:", err);
    req.flash("error", "Something went wrong.");
    res.redirect("/login");
  }
});

app.post("/register", verifyRecaptcha, async (req, res) => {
  let { email, age, password, name, username, Confirm_password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      req.flash("error", "User already exists");
      return res.redirect("/login");
    }
    if (Confirm_password === password) {
      let hashedPassword = await bcrypt.hash(password, 10);
      const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();
      let newUser = await User.create({
        username,
        email,
        age,
        name,
        password: hashedPassword,
        verificationToken,
        verificationTokenExpiresAt: Date.now() + 24 * 60 * 60 * 1000,
      });

      let token = jwt.sign(
        { email, userid: newUser._id, isVerified: false },
        jwtSecret,
        { expiresIn: "1h" }
      );
      res.cookie("token", token, { httpOnly: true });

      await sendVerificationEmail(email, verificationToken);

      req.flash("success", "Registered successfully! Please verify your email.");
      res.redirect("/verify-otp");
    } else {
      req.flash("error", "Password and Confirm Password do not match");
      return res.render("index", {
        name: name || "",
        username: username || "",
        email: email || "",
        age: age || "",
        success_msg: req.flash("success"),
        error_msg: req.flash("error"),
      });
    }
  } catch (err) {
    console.error("❌ Error during registration:", err);
    req.flash("error", "Something went wrong.");
    res.render("index", {
      name: name || "",
      username: username || "",
      email: email || "",
      age: age || "",
      success_msg: req.flash("success"),
      error_msg: req.flash("error"),
    });
  }
});

app.get("/register", (req, res) => {
  res.render("index", {
    name: req.query.name || "",
    username: req.query.username || "",
    email: req.query.email || "",
    age: req.query.age || "",
    success_msg: req.flash("success"),
    error_msg: req.flash("error"),
  });
});

app.get("/verify-otp", isVerificationPending, (req, res) => {
  res.render("otp");
});

app.post("/verify-otp", isVerificationPending, async (req, res) => {
  try {
    const { otp } = req.body;
    const user = await User.findOne({
      verificationToken: otp,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!user) {
      req.flash("error", "Invalid or expired OTP.");
      return res.redirect("/verify-otp");
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;
    await user.save();

    let token = jwt.sign(
      { email: user.email, userid: user._id, isVerified: true },
      jwtSecret,
      { expiresIn: "1h" }
    );
    res.cookie("token", token, { httpOnly: true });

    await sendWelcomeEmail(user.email, user.name);

    req.flash("success", "Email verified successfully!");
    res.redirect("/profile");
  } catch (error) {
    console.error("❌ Error during email verification:", error);
    req.flash("error", "Something went wrong.");
    res.redirect("/verify-otp");
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.flash("success", "You have been logged out");
  res.redirect("/login");
});

app.get("/profile/upload", isLoggedIn, (req, res) => {
  res.render("profileupload");
});

app.post("/upload", isLoggedIn, upload.single("image"), async (req, res) => {
  try {
    let user = await User.findOne({ email: req.user.email });

    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/profile");
    }

    user.profilepic = req.file.filename;
    await user.save();

    req.flash("success", "Profile picture updated successfully!");
    res.redirect("/profile");
  } catch (err) {
    console.error("❌ Error uploading profile picture:", err);
    req.flash("error", "Something went wrong. Please try again.");
    res.redirect("/profile");
  }
});

app.get("/forgot",(req,res)=>{
  res.render("forgot_password")
})

app.post("/forgotemail", verifyRecaptcha, async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/forgot");
    }

    const verificationToken = Math.floor(100000 + Math.random() * 900000).toString();
    user.verificationToken = verificationToken;
    user.verificationTokenExpiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes expiry
    await user.save();

    await sendResetingVerificationEmail(email, verificationToken);

    req.flash("success", "OTP sent to your email. Please verify.");
    res.redirect(`/verify-reset?email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error("❌ Error sending OTP:", err);
    req.flash("error", "Something went wrong. Please try again.");
    res.redirect("/forgot");
  }
});

app.get("/verify-reset", (req, res) => {
  const { email } = req.query;
  if (!email) {
    req.flash("error", "Invalid request.");
    return res.redirect("/forgot");
  }
  res.render("verify_reset", { email });
});

app.post("/verify-reset", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({
      email,
      verificationToken: otp,
      verificationTokenExpiresAt: { $gt: Date.now() },
    });

    if (!user) {
      req.flash("error", "Invalid or expired OTP.");
      return res.redirect(`/verify-reset?email=${encodeURIComponent(email)}`);
    }

    user.verificationToken = undefined;
    user.verificationTokenExpiresAt = undefined;
    await user.save();

    req.flash("success", "OTP verified. You can now reset your password.");
    res.redirect(`/reset?email=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error("❌ Error verifying OTP:", err);
    req.flash("error", "Something went wrong. Please try again.");
    res.redirect(`/verify-reset?email=${encodeURIComponent(email)}`);
  }
});

app.get("/reset", (req, res) => {
  const { email } = req.query;
  if (!email) {
    req.flash("error", "Invalid request.");
    return res.redirect("/forgot");
  }
  res.render("reset_password", { email });
});

app.post("/resetpassword", verifyRecaptcha, async (req, res) => {
  const { email, password, Confirm_password } = req.body;

  if (password !== Confirm_password) {
    req.flash("error", "Password and Confirm Password do not match.");
    return res.redirect(`/reset?email=${encodeURIComponent(email)}`);
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      req.flash("error", "User not found.");
      return res.redirect("/login");
    }

    user.password = await bcrypt.hash(password, 10);
    await user.save();

    req.flash("success", "Password reset successfully! Please log in.");
    await sendpasswordchangetemplate(user.email,user.name);
    res.redirect("/login");
  } catch (err) {
    console.error("❌ Error resetting password:", err);
    req.flash("error", "Something went wrong. Please try again.");
    res.redirect(`/reset?email=${encodeURIComponent(email)}`);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
