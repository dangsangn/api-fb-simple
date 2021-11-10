const router = require("express").Router();
const verifyToken = require("../middleware/auth");
const Conversation = require("../models/Conversation");

//post a new conversation
router.post("/", verifyToken, async (req, res) => {
  const conversation = new Conversation({
    members: [req.userId, req.body.receiverId],
  });
  try {
    const newConversation = await conversation.save();
    res.json({ success: true, conversation: newConversation });
  } catch (error) {
    res.status(500).json(error);
  }
});

//get list conversation
router.get("/", verifyToken, async (req, res) => {
  try {
    const conversations = await Conversation.find({
      members: { $in: [req.userId] },
    });
    res.json({ success: true, conversations });
  } catch (error) {
    res.status(500).json(error);
  }
});

//get a conversation
router.get("/:id", verifyToken, async (req, res) => {
  try {
    const conversation = await Conversation.findOne({
      members: { $all: [req.userId, req.params.id] },
    });
    res.json({ success: true, conversation });
  } catch (error) {
    res.status(500).json(error);
  }
});

module.exports = router;
