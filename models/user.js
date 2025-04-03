const mongoose = require("mongoose");
require('dotenv').config();

mongoose.connect(process.env.DB_URL, {
    tls: true
});

const userSchema = new mongoose.Schema({
    username: String,
    name: String,
    age: Number,
    email: String,
    password: String,
    profilepic: {
        type: String,
        default: "default.jpg"
    },
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }],
    isVerified: {
        type: Boolean,
        default: false,
    },
    verificationToken: String,
    verificationTokenExpiresAt: Date,
});

module.exports = mongoose.model("User", userSchema);
