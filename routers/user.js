const router = require("express").Router();

const verifyToken = require("../middleware/auth");
const User = require("../models/User");

//update user
router.put("/", verifyToken, async (req, res) => {
  try {
    const userUpdate = await User.findOneAndUpdate(
      { _id: req.userId },
      req.body,
      {
        new: true,
      }
    );
    res.json({ success: true, userUpdate });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//get profile
router.get("/:id", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "not found user" });
    }
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//follow and unfollow a user
router.put("/:id/follow", verifyToken, async (req, res) => {
  try {
    const currentUser = await User.findById(req.userId);
    const friend = await User.findById(req.params.id);
    if (!friend) {
      res.status(400).json({ success: false, message: "user not found" });
    }
    console.log(currentUser.followings);
    if (!currentUser.followings.includes(req.params.id)) {
      await currentUser.updateOne(
        { $push: { followings: req.params.id } },
        { new: true }
      );
      await friend.updateOne(
        { $push: { followers: req.userId } },
        { new: true }
      );
    } else {
      await currentUser.updateOne(
        { $pull: { followings: req.params.id } },
        { new: true }
      );
      await friend.updateOne(
        { $pull: { followers: req.userId } },
        { new: true }
      );
    }
    const newUser = await User.findById(req.userId);
    res.json({ success: true, newUser });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

module.exports = router;
