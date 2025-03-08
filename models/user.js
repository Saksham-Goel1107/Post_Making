const mongoose = require("mongoose");
require('dotenv').config()

// ✅ Connect to MongoDB (Avoid multiple connections in different files)
// mongoose.connect(process.env.DB_URL_LOCAL, {
mongoose.connect(process.env.DB_URL, {

    tls:true
});

const userSchema = new mongoose.Schema({
    username: String,
    name: String,
    age: Number,
    email: String,
    password: String,
    posts: [{ type: mongoose.Schema.Types.ObjectId, ref: "Post" }] // ✅ Fixed: Reference matches Post model
});

module.exports = mongoose.model("User", userSchema);
