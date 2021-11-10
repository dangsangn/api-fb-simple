const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const CommentSchema = new Schema({
  postId: {
    type: Schema.Types.ObjectId,
    ref: "posts",
  },
  userId: {
    type: Schema.Types.ObjectId,
    ref: "users",
  },
  content: {
    type: String,
  },
  img: {
    type: String,
    default: "",
  },
  likes: {
    type: Array,
    default: [],
  },
});

module.exports = mongoose.model("comments", CommentSchema);
