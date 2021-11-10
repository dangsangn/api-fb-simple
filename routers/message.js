const router = require("express").Router();
const verifyToken = require("../middleware/auth");
const Conversation = require("../models/Conversation");
const Message = require("../models/Message");

//add a messs
router.post("/", verifyToken, async (req, res) => {
  const message = new Message({
    conversationId: req.body.conversationId,
    sender: req.userId,
    content: req.body.content,
  });
  try {
    const newMessage = await message.save();
    res.json({ success: true, message: newMessage });
  } catch (error) {
    res.status(500).json(error);
  }
});

//get message of a conversation
router.get("/:conversationId", verifyToken, async (req, res) => {
  try {
    const messages = await Message.find({
      conversationId: req.params.conversationId,
    });
    res.json({ success: true, messages });
  } catch (error) {
    res.status(500).json(error);
  }
});

module.exports = router;
