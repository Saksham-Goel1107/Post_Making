// ✅ Install required dependencies using:
// npm install express ejs bcrypt cookie-parser mongoose jsonwebtoken connect-flash express-session dotenv

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
require('dotenv').config()
const app = express();
if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET is not set in environment variables!");
}
const jwtSecret = process.env.JWT_SECRET;

// ✅ Set EJS as view engine
app.set("view engine", "ejs");

// ✅ Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

// ✅ Session for Flash Messages
app.use(
  session({
    secret: jwtSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 5000 }, // Flash message auto-remove
  })
);
app.use(flash());

// ✅ Middleware to pass flash messages to EJS
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success");
  res.locals.error_msg = req.flash("error");
  next();
});

// ✅ Authentication Middleware
function isLoggedIn(req, res, next) {
  if (!req.cookies.token) {
    req.flash("error", "Please log in first");
    return res.redirect("/login");
  }

  try {
    let data = jwt.verify(req.cookies.token, jwtSecret);
    req.user = data;
    next();
  } catch (err) {
    res.clearCookie("token");
    req.flash("error", "Session expired, please log in again");
    res.redirect("/login");
  }
}

// initial Routes
app.get("/", (req, res) => res.render("index"));

//  Login Page
app.get("/login", (req, res) => {
  if (req.cookies.token) {
    try {
      jwt.verify(req.cookies.token, jwtSecret); // Check if token is valid
      req.flash("success", "You are already logged in!");
      return res.redirect("/profile");
    } catch (err) {
      res.clearCookie("token");
    }
  }
  res.render("login");
});

// Profile Route 
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

      // Ensure likes array exists
      if (!post.likes) {
          post.likes = [];
      }

      // Check if user already liked the post (prevents duplicate likes)
      if (!post.likes.includes(req.user.userid)) {
          post.likes.push(req.user.userid);
          await post.save();
          req.flash("success", "Post liked!");
      } else {
          req.flash("error", "You already liked this post.");
      }
  } catch (err) {
      console.error("❌ Error liking post:", err);
      req.flash("error", "Something went wrong.");
  }
  res.redirect("/profile");
});

  

// ✅ Edit Post Route (Show Edit Form)
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
  
      post.content = content; // ✅ Update post content
      await post.save(); // ✅ Save changes
  
      req.flash("success", "Post updated successfully!");
    } catch (err) {
      console.error("❌ Error updating post:", err);
      req.flash("error", "Something went wrong.");
    }
  
    res.redirect("/profile");
  });
  

// ✅ Login Logic
app.post("/login", async (req, res) => {
  let { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      req.flash("error", "Invalid email or password");
      return res.redirect("/login");
    }

    let token = jwt.sign({ email, userid: user._id }, jwtSecret, { expiresIn: "1h" });
    res.cookie("token", token, { httpOnly: true });

    req.flash("success", "Login successful!");
    res.redirect("/profile");
  } catch (err) {
    console.error("❌ Error during login:", err);
    req.flash("error", "Something went wrong.");
    res.redirect("/login");
  }
});

// ✅ Register User
app.post("/register", async (req, res) => {
  let { email, age, password, name, username } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      req.flash("error", "User already exists");
      return res.redirect("/login");
    }

    let hashedPassword = await bcrypt.hash(password, 10);

    let newUser = await User.create({
      username,
      email,
      age,
      name,
      password: hashedPassword,
    });

    let token = jwt.sign({ email, userid: newUser._id },jwtSecret, { expiresIn: "1h" });
    res.cookie("token", token, { httpOnly: true });

    req.flash("success", "Registered successfully! Please log in.");
    res.redirect("/login");
  } catch (err) {
    console.error("❌ Error during registration:", err);
    req.flash("error", "Something went wrong.");
    res.redirect("/");
  }
});

// ✅ Logout
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.flash("success", "You have been logged out");
  res.redirect("/login");
});

//  Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
