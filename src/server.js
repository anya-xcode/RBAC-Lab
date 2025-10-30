const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Secret key for JWT signing
const JWT_SECRET = "newtonschoolsecret";

// In-memory user data
const users = [
  { username: "yash", password: "123", role: "admin" },
  { username: "ankit", password: "123", role: "teacher" },
  { username: "anurag", password: "123", role: "student" },
];

// --- LOGIN ROUTE ---
app.post("/login", (req, res) => {
  const { username, password , role} = req.body;
  const user = users.find((u) => u.username === username && u.password === password && u.role === role);
  if (!user) {
    return res.status(401).send("Invalid credentials");
  } 
  const token = jwt.sign({ username, role }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// --- AUTH MIDDLEWARE ---
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: "header is  missing" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).send({ message: "Invalid token" });

  }
  
};


// --- ROLE CHECK MIDDLEWARE ---
const authorize = (allowedRoles) => (req, res, next) => {
  if (!allowedRoles.includes(req.user.role)) {
    return res.status(403).send({ message: "Access denied" });
  }
  next(); 
  
};

// --- PROTECTED ROUTES ---
app.get("/admin", authenticate, authorize(["admin"]), (req, res) => {
  res.send("Welcome, admin!");
});

app.get("/teacher", authenticate, authorize(["teacher"]), (req, res) => {
  res.send("Welcome, teacher!");
});

app.get("/student", authenticate, authorize(["student"]), (req, res) => {
  res.send("Welcome, student!");
});

module.exports = app;

// --- RUN DIRECTLY IF NOT TESTING ---
const PORT = 3300;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
