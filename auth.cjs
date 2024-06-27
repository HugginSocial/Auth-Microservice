const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Sequelize, DataTypes } = require("sequelize");
const dotenv = require("dotenv");
const cors = require("cors");

// Load environment variables from .env file
dotenv.config();

// Initialize Sequelize
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: "./auth_database.sqlite",
});

// Define User model
const User = sequelize.define("User", {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Define RefreshToken model
const RefreshToken = sequelize.define("RefreshToken", {
  token: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
});

// Sync the database
sequelize.sync().then(() => {
  app.use(express.json());
  app.use(cors());

  app.get("/users", async (req, res) => {
    try {
      const users = await User.findAll();
      res.json(users);
    } catch (error) {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }
  });

  app.post("/users", async (req, res) => {
    try {
      if (await User.findOne({ where: { username: req.body.username } })) {
        return res.status(400).send("User already exists");
      }
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      await User.create({ username: req.body.username, password: hashedPassword });
      res.status(201).send("User created successfully");
    } catch (error) {
      console.error(error, "User creation failed");
      res.status(500).send("Internal Server Error");
    }
  });

  app.post("/users/login", async (req, res) => {
    try {
      const user = await User.findOne({ where: { username: req.body.username } });
      if (user == null) {
        return res.status(400).send("Cannot find user");
      }
      if (await bcrypt.compare(req.body.password, user.password)) {
        const accessToken = generateAccessToken({ username: user.username });
        const refreshToken = jwt.sign(
          { username: user.username },
          process.env.REFRESH_TOKEN_SECRET
        );
        await RefreshToken.create({ token: refreshToken });
        res.json({ accessToken: accessToken, refreshToken: refreshToken });
      } else {
        res.send("Not Allowed");
      }
    } catch (error) {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }
  });

  app.post("/token", async (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    const tokenExists = await RefreshToken.findOne({
      where: { token: refreshToken },
    });
    if (!tokenExists) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      const accessToken = generateAccessToken({ username: user.username });
      res.json({ accessToken: accessToken });
    });
  });

  app.delete("/logout", async (req, res) => {
    await RefreshToken.destroy({ where: { token: req.body.token } });
    res.sendStatus(204);
  });

  function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
      expiresIn: "35600s",
    });
  }

  app.listen(4000, () => console.log("server started"));
});
