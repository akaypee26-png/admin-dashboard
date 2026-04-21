const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

const SECRET = "mysecretkey";

// ================= DB =================
mongoose.connect("mongodb+srv://akp:123@cluster0.gqbkghd.mongodb.net/usersDB?retryWrites=true&w=majority")
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error(err));

// ================= SCHEMAS =================

// 🔐 ADMIN (for login)
const adminSchema = new mongoose.Schema({
  name: String,
  username: { type: String, unique: true },
  password: String
});

const Admin = mongoose.model("Admin", adminSchema);

// 👥 USERS (for dashboard)
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
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

app.get("/me", auth, async (req, res) => {
  try {
    const admin = await Admin.findById(req.user.id);

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    res.json({
      name: admin.name,
      username: admin.username
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

// ================= AUTH ROUTES =================

// Signup ADMIN
app.post("/auth/signup", async (req, res) => {
  try {
    const { name, username, password } = req.body;

    const exists = await Admin.findOne({ username });
    if (exists) return res.status(400).json({ error: "Admin exists" });

    const hashed = await bcrypt.hash(password, 10);

    const admin = new Admin({
      name,
      username,
      password: hashed
    });

    await admin.save();

    res.json({ message: "Admin created" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// Login ADMIN
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(400).json({ error: "Invalid user" });

    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(400).json({ error: "Wrong password" });

   const token = jwt.sign(
  { id: admin._id },
  SECRET,
  { expiresIn: "30s" } // 🔥 expires in 1 hour
);

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ================= USER ROUTES =================

// Get users
app.get("/users", async (req, res) => {
  const users = await User.find();
  res.json(users);
});

// Add user (protected)
app.post("/users", auth, async (req, res) => {
  const { name, username } = req.body;

  const user = new User({ name, username });
  await user.save();

  res.json(user);
});

// Update user
app.put("/users/:id", auth, async (req, res) => {
  const { name } = req.body;

  const user = await User.findByIdAndUpdate(
    req.params.id,
    { name },
    { new: true }
  );

  res.json(user);
});

// Delete user
app.delete("/users/:id", auth, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

// ================= STATIC =================
app.use(express.static("public"));

// ================= START =================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});