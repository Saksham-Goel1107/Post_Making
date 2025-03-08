const mongoose = require("mongoose"); // ✅ Add this line

const postSchema = new mongoose.Schema({
  title: String,
  content: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User", default: [] }]
});

// Ensure likes is always an array
postSchema.pre("save", function (next) {
  if (!this.likes) {
    this.likes = [];
  }
  next();
});

module.exports = mongoose.model("Post", postSchema);
