const router = require("express").Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const verifyToken = require("../middleware/auth");

const User = require("../models/User");

//check user is login
router.get("/", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "user not found " });
    }
    res.json({ success: true, user });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//register
router.post("/register", async (req, res) => {
  const { username, email, password, password_confirm } = req.body;
  if (!username || !password || !password_confirm || !email) {
    return res.status(400).json({ succes: false, message: "enter empty" });
  }

  if (password !== password_confirm) {
    return res
      .status(400)
      .json({ succes: false, message: "password confirm incorrect" });
  }
  try {
    const userByUsername = await User.findOne({ username });
    const userByEmail = await User.findOne({ email });

    if (userByUsername) {
      return res.status(200).json({ succes: false, message: "user is exist" });
    }
    if (userByEmail) {
      return res.status(200).json({ succes: false, message: "email is exist" });
    }
    //all good
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    //return token
    const accessToken = jwt.sign(
      { userId: newUser._id },
      process.env.ACCESS_TOKEN_SECRET
    );
    res.json({ success: true, accessToken });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

//login user
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "enter empty" });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "email incorrect" });
    }
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!passwordValid) {
      return res
        .status(400)
        .json({ succes: false, message: "password incorrect" });
    }
    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.ACCESS_TOKEN_SECRET
    );
    res.json({ success: true, accessToken });
  } catch (error) {
    res.status(500).json({ success: false, message: error });
  }
});

module.exports = router;
