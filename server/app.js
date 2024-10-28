const express = require("express");
const jwt = require("jsonwebtoken");
const logger = require("morgan");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();

const targetUrl =
  process.env.NODE_ENV === "production"
    ? "<INSERT DEPLOYED FRONTEND LINK>"
    : "http://localhost:3000";
const corsOptions = {
  origin: (origin, callback) => {
    if (origin === targetUrl) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS").message, false);
    }
  },
  methods: ["GET"],
  maxAge: 3600,
  credentials: true,
};

app.use(cors(corsOptions));
app.use(logger("dev"));
app.use(express.json());
app.use(helmet());
app.use(cookieParser());

const secretKey = process.env.SECRET_KEY;
const hashedPassword = bcrypt.hashSync(process.env.USER_PASSWORD, 10);
const users = [{ id: 1, username: "admin", password: hashedPassword }];

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign(
      { id: user.id, username: user.username },
      secretKey,
      { expiresIn: "3m" }
    );
    res.json({ token });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

app.get("/protected", (req, res) => {
  const token = req.cookies.jwtToken;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    res.json({ message: "Welcome to the protected route!", decoded });
  });
});

app.get("/testing", (req, res) => {
  res.send("App is working!");
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
