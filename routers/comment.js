const router = require("express").Router();
const User = require("../models/User");
const Comment = require("../models/Comment");
const verifyToken = require("../middleware/auth");

//get list comment
router.get("/:id", verifyToken, async (req, res) => {
  try {
    const listComment = await Comment.find({ postId: req.params.id });
    const listCommentUser = await Promise.all(
      listComment.map(async (comment) => {
        const user = await User.findById(comment.userId);
        return {
          img: comment.img,
          likes: comment.likes,
          _id: comment._id,
          postId: comment.postId,
          userId: comment.userId,
          content: comment.content,
          username: user.username,
          profilePicture: user.profilePicture,
        };
      })
    );
    res.json({ success: true, comments: listCommentUser });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//create a comment
router.post("/:id", verifyToken, async (req, res) => {
  const { content, img } = req.body;
  const user = await User.findById(req.userId);
  if (!content) {
    return res.status(400).json({ success: false, message: "content empty" });
  }
  try {
    const newComment = new Comment({
      postId: req.params.id,
      userId: req.userId,
      content,
      img,
    });
    await newComment.save();
    res.json({
      success: true,
      comment: {
        img: newComment.img,
        likes: newComment.likes,
        _id: newComment._id,
        postId: newComment.postId,
        userId: newComment.userId,
        content: newComment.content,
        username: user.username,
        profilePicture: user.profilePicture,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

module.exports = router;
