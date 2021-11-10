require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const multer = require("multer");
const path = require("path");

const app = express();

const routerAuth = require("./routers/auth");
const routerPost = require("./routers/post");
const routerUser = require("./routers/user");
const routerComment = require("./routers/comment");
const routerConversation = require("./routers/conversation");
const routerMessage = require("./routers/message");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.URL_MONGO_DB, {
      useCreateIndex: true,
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useFindAndModify: true,
    });
    console.log("Mongoose connected");
  } catch (error) {
    console.log(error.message);
    process.exit(1);
  }
};

connectDB();

//middleware
app.use(express.json());
app.use(helmet());
app.use(morgan("common"));
app.use(cors());

app.use("/api/images", express.static(path.join(__dirname, "public/images")));

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/images");
  },
  filename: (req, file, cb) => {
    cb(null, req.body.name);
  },
});

const upload = multer({ storage: storage });
app.post("/api/upload", upload.single("file"), (req, res) => {
  try {
    return res.status(200).json({ success: true, message: "Upload success" });
  } catch (error) {
    console.log(error);
  }
});

//router
app.use("/api/auth", routerAuth);
app.use("/api/posts", routerPost);
app.use("/api/user", routerUser);
app.use("/api/comment", routerComment);
app.use("/api/conversation", routerConversation);
app.use("/api/message", routerMessage);

const PORT = process.env.PORT || 6868;

const server = app.listen(PORT, () => console.log("Server is running"));

//socket io
const socket = require("socket.io");
const io = socket(server, {
  cors: {
    origin: "http://localhost:3000",
  },
});

const users = [];

//add a user
const addUser = (userId, socketId) => {
  userId &&
    !users.some((user) => user.userId === userId) &&
    users.push({ userId, socketId });
};

//remove a user
const removeUser = (socketId) => {
  users = users.filter((user) => user.socketId !== socketId);
};

//get a user
const getUser = (userId) => {
  return users.find((user) => user.userId === userId);
};

io.on("connection", (socket) => {
  //when a connection
  // console.log("connection: ", socket);

  //take userId and socketId from user
  socket.on("addUser", (userId) => {
    addUser(userId, socket.id);
    io.emit("getUsers", users);
  });

  //send and get message
  socket.on("sendMessage", ({ senderId, receiverId, message }) => {
    const receiver = getUser(receiverId);
    io.to(receiver?.socketId).emit("getMessage", { senderId, message });
    console.log(message);
  });

  //when disconnect a user
  socket.on("disconection", (userId) => {
    removeUser(userId);
    io.emit("getUsers", users);
  });
});
