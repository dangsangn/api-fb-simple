const router = require("express").Router();
const Post = require("../models/Post");
const User = require("../models/User");
const verifyToken = require("../middleware/auth");

//create a post
router.post("/", verifyToken, async (req, res) => {
  try {
    const post = new Post({ ...req.body, userId: req.userId });
    await post.save();
    res.json({ success: true, post });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//update post
router.put("/:id", verifyToken, async (req, res) => {
  try {
    const postUpdate = await Post.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      req.body,
      { new: true }
    );
    if (!postUpdate) {
      return res
        .status(400)
        .json({ success: false, message: "post not found" });
    }
    res.json({ success: true, post: postUpdate });
  } catch (error) {
    res.json({ success: false, message: error });
  }
});

//delete post
router.delete("/:id", verifyToken, async (req, res) => {
  try {
    const postDelete = await Post.findOneAndDelete({
      _id: req.params.id,
      userId: req.userId,
    });

    if (!postDelete) {
      return res
        .status(400)
        .json({ success: false, message: "post not found" });
    }
    res.json({ success: true, post: postDelete });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//get a post
router.get("/:id", verifyToken, async (req, res) => {
  try {
    const post = await Post.findOne({ _id: req.params.id, userId: req.userId });
    if (!post) {
      return res
        .status(400)
        .json({ success: false, message: "not found post" });
    }
    res.json({ success: true, post });
  } catch (error) {
    res.json({ success: false, message: error });
  }
});

//like and dislike
router.put("/:id/like", verifyToken, async (req, res) => {
  try {
    let post = await Post.findOne({ _id: req.params.id });
    if (!post) {
      return res
        .status(400)
        .json({ success: false, message: "not found post" });
    } else {
      if (!post.likes.includes(req.userId)) {
        await post.updateOne({ $push: { likes: req.userId } }, { new: true });
      } else {
        await post.updateOne({ $pull: { likes: req.userId } }, { new: true });
      }
      let newPost = await Post.findOne({ _id: req.params.id });
      res.json({ success: true, post: newPost });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//get list post user and friend of user
router.get("/listPost/all", verifyToken, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    const currentUserPost = await Post.find({ userId: req.userId });

    const friendPost =
      (await Promise.all(
        currentUser.followings.map((friendId) =>
          Post.find({ userId: friendId })
        )
      )) || [];
    res.json({ success: true, listPost: [...currentUserPost, ...friendPost] });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

module.exports = router;
