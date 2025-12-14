const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const router = express.Router();

const users = []; 


router.post("/register",
  body("email").isEmail(),
  body("password").isLength({ min: 6 }),
  async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({ name, email, password: hashedPassword });

    res.json({ message: "User registered successfully" });
  }
);


router.post("/login",
  body("email").isEmail(),
  async (req, res) => {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).json({ message: "Invalid email or password" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid email or password" });

    
    const token = jwt.sign({ email }, "SECRET_KEY", { expiresIn: "1h" });

    res.json({ token });
  }
);

module.exports = router;
