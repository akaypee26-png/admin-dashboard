require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET;

// ================= DB =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// ================= SCHEMAS =================

// 🔐 ADMIN (login users)
const adminSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: String,
  role: { type: String, default: "user" } // ✅ default user
});

const Admin = mongoose.model("Admin", adminSchema);

// 👥 USERS (dashboard data)
const userSchema = new mongoose.Schema({
  name: String,
  username: String
});

const User = mongoose.model("User", userSchema);

// ================= AUTH MIDDLEWARE =================
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: "No token" });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded; // contains id + role
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ✅ ADMIN CHECK
function isAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Access denied (admin only)" });
  }
  next();
}

// ================= GET LOGGED USER =================
app.get("/me", auth, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id);

    if (!admin) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      name: admin.name,
      username: admin.username,
      role: admin.role // ✅ IMPORTANT
    });

  } catch (err) {
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

// ================= AUTH ROUTES =================

// Signup
app.post("/auth/signup", async (req, res) => {
  try {
    const { name, username, password, role } = req.body;

    const exists = await Admin.findOne({ username });
    if (exists) return res.status(400).json({ error: "User already exists" });

    const hashed = await bcrypt.hash(password, 10);

    const user = new Admin({
      name,
      username,
      password: hashed,
      role: role || "user" // ✅ default user
    });

    await user.save();

    res.json({ message: "Account created" });

  } catch (err) {
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await Admin.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid user" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign(
      { id: user._id, role: user.role }, // ✅ include role
      SECRET,
      { expiresIn: "5m" }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ================= USER ROUTES =================

// Get users (public or protected — your choice)
app.get("/users", auth, async (req, res) => {
  const users = await User.find();
  res.json(users);
});

// Add user (ADMIN ONLY)
app.post("/users", auth, isAdmin, async (req, res) => {
  const { name, username } = req.body;

  const user = new User({ name, username });
  await user.save();

  res.json(user);
});

// 🔥 FIXED UPDATE (you missed :id ❌)
app.put("/users/:id", auth, isAdmin, async (req, res) => {
  const { name } = req.body;

  const user = await User.findByIdAndUpdate(
    req.params.id,
    { name },
    { new: true }
  );

  res.json(user);
});

// 🔥 FIXED DELETE (you missed :id ❌)
app.delete("/users/:id", auth, isAdmin, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

// ================= STATIC =================
app.use(express.static("public"));

// ================= START =================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});