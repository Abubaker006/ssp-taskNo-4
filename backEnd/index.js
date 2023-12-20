import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import User from "./Models/User.js";
import cors from "cors";
import bcrypt from "bcrypt";

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "30mb", extended: true }));

const saltRounds = 10;

app.post("/signUp", async (req, res) => {
  try {
    // Check if email and password are provided
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Both email and password are required." });
    }

    // Hashing the password
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.log(`There was an error in Hashing: ${err}`);
        res
          .status(500)
          .json({ error: "An error occurred while hashing the password." });
      } else {
        try {
          const newUser = new User({
            email,
            password: hash,
          });

          await newUser.save();

          // Respond with a success message and the created user
          res.status(201).json(newUser);
          console.log("User Created");
        } catch (saveError) {
          console.error(`Error saving user: ${saveError}`);
          res
            .status(500)
            .json({ error: "An error occurred while creating the user." });
        }
      }
    });
  } catch (error) {
    console.error(`Error in the code: ${error}`);
    res
      .status(500)
      .json({ error: "An error occurred while processing the request." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      // User not found
      return res.status(401).json({ error: "Invalid credentials." });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
      res.status(200).json({ message: "Login successful" });
      console.log("Taking you to the Secrets Page");
    } else {
      res.status(401).json({ error: "Invalid credentials." });
    }
  } catch (error) {
    console.error(`Error in login route: ${error}`);
    res
      .status(500)
      .json({ error: "An error occurred while processing your request." });
  }
});

const PORT = process.env.PORT || 3001;
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    app.listen(PORT, () => console.log(`Server has Started On Port: ${PORT}`));
  })
  .catch((error) => console.log(`${error} did not connect`));
