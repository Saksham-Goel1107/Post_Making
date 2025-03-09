const mongoose = require("mongoose"); // ✅ Add this line

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }]
});

module.exports = mongoose.model("Post", postSchema);
