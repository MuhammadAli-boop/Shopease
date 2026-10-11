require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");

// Raaz .env file se aate hain (code mein koi password nahi)
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PORT = process.env.PORT || 3000;

if (!MONGO_URL || !JWT_SECRET || !ADMIN_PASSWORD) {
  console.log("Zaroori raaz nahi mile. .env file check karo (MONGO_URL, JWT_SECRET, ADMIN_PASSWORD).");
  process.exit(1);
}

const app = express();

// Online hosting ke peeche asli IP pehchanne ke liye
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

// Sirf ye 2 pages browser mein khulenge (baqi files band rahengi)
app.get("/shop.html", (req, res) => {
  res.sendFile(path.join(__dirname, "shop.html"));
});

app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Database se connection
mongoose
  .connect(MONGO_URL)
  .then(() => console.log("Database connect ho gaya!"))
  .catch((err) => console.log("Database error:", err.message));

// Products ki list
const products = [
  { id: 1, name: "Classic T-Shirt", price: 1200, category: "Fashion", image: "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=600" },
  { id: 2, name: "Running Shoes", price: 4500, category: "Fashion", image: "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=600" },
  { id: 3, name: "Wireless Headphones", price: 3500, category: "Electronics", image: "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=600" },
  { id: 4, name: "Smart Watch", price: 6000, category: "Electronics", image: "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=600" },
  { id: 5, name: "Travel Backpack", price: 2800, category: "Accessories", image: "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=600" },
  { id: 6, name: "Sunglasses", price: 1500, category: "Accessories", image: "https://images.unsplash.com/photo-1511499767150-a48a237f0083?w=600" },
  { id: 7, name: "Table Lamp", price: 2200, category: "Home", image: "https://images.unsplash.com/photo-1507473885765-e6ed057f782c?w=600" },
  { id: 8, name: "Coffee Mug", price: 650, category: "Home", image: "https://images.unsplash.com/photo-1514228742587-6b1558fcca3d?w=600" },
  { id: 9, name: "CAT", price: 25000, category: "ANIMAL", image: "https://cdn.theatlantic.com/thumbor/Kto-jp-IrA7TydSu5W5uB1FBDmA=/0x131:2555x1568/1952x1098/media/img/mt/2017/06/shutterstock_319985324/original.jpg" },
  { id: 10, name: "Bluetooth Speaker", price: 3200, category: "Electronics", image: "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQCihnHqkDqcVir9aqRrZmy8jem3q07ijWdqxW8t88d1Q&s=10" },
];

// User database mein is shakal mein save hoga
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String, // scrambled (hash) form mein
  date: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// Order database mein is shakal mein save hoga
const orderSchema = new mongoose.Schema({
  orderNumber: Number,
  userId: String,
  customerName: String,
  phone: String,
  address: String,
  items: [{ id: Number, quantity: Number }],
  total: Number,
  date: { type: Date, default: Date.now },
});

const Order = mongoose.model("Order", orderSchema);

// Contact message database mein is shakal mein save hoga
const messageSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
  date: { type: Date, default: Date.now },
});

const Message = mongoose.model("Message", messageSchema);

// Customer ke login ko check karne wala helper
function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (!data.id) throw new Error("not a customer token");
    req.userId = data.id;
    next();
  } catch (err) {
    res.status(401).json({ message: "Pehle login karo" });
  }
}

// Admin ke login ko check karne wala helper
function adminAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (data.admin !== true) throw new Error("not an admin token");
    next();
  } catch (err) {
    res.status(401).json({ message: "Admin login zaroori hai" });
  }
}

// Do texts ko barabar check karne ka mehfooz tareeqa
function sameText(a, b) {
  const x = crypto.createHash("sha256").update(a).digest();
  const y = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(x, y);
}

// Seedha link kholne par shop page dikhao
app.get("/", (req, res) => {
  res.redirect("/shop.html");
});

app.get("/products", (req, res) => {
  res.json(products);
});

// Signup: naya account banao
app.post("/signup", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({ message: "Sab fields bharo" });
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      return res.status(400).json({ message: "Sahi email likho" });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({ message: "Password kam az kam 6 characters ka rakho" });
    }

    if (name.length > 100 || email.length > 100) {
      return res.status(400).json({ message: "Text bohat lamba hai" });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ message: "Ye email pehle se registered hai" });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hash });

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Account ban gaya!", token, name: user.name });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ message: "Ye email pehle se registered hai" });
    }
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

// Login: email aur password check karo
app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ message: "Email aur password bharo" });
    }

    const user = await User.findOne({ email });
    const ok = user ? await bcrypt.compare(password, user.password) : false;

    if (!ok) {
      return res.status(400).json({ message: "Email ya password galat hai" });
    }

    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Login ho gaya!", token, name: user.name });
  } catch (err) {
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

// Naya order save karo (sirf login customer kar sakta hai)
app.post("/orders", auth, async (req, res) => {
  try {
    const items = req.body.items;
    const customerName = String(req.body.customerName || "").trim();
    const phone = String(req.body.phone || "").trim();
    const address = String(req.body.address || "").trim();

    if (!customerName || !phone || !address) {
      return res.status(400).json({ message: "Naam, phone aur address bharo" });
    }

    if (!/^[0-9+\-\s]{7,15}$/.test(phone)) {
      return res.status(400).json({ message: "Sahi phone number likho" });
    }

    if (customerName.length > 100 || address.length > 300) {
      return res.status(400).json({ message: "Text bohat lamba hai" });
    }

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "Cart khali hai" });
    }

    let total = 0;
    const cleanItems = [];

    for (const item of items) {
      const product = products.find((p) => p.id === item.id);
      if (!product || !Number.isInteger(item.quantity) || item.quantity <= 0) {
        return res.status(400).json({ message: "Cart mein masla hai" });
      }
      total += product.price * item.quantity;
      cleanItems.push({ id: item.id, quantity: item.quantity });
    }

    const orderNumber = (await Order.countDocuments()) + 1;
    const order = await Order.create({
      orderNumber,
      userId: req.userId,
      customerName,
      phone,
      address,
      items: cleanItems,
      total,
    });

    res.json({ message: "Order ho gaya!", orderId: order.orderNumber, total });
  } catch (err) {
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

// My Orders: login customer ke sirf apne orders
app.get("/my-orders", auth, async (req, res) => {
  try {
    const mine = await Order.find({ userId: req.userId }).sort({ date: -1 });

    const result = mine.map((o) => ({
      orderNumber: o.orderNumber,
      date: o.date,
      total: o.total,
      items: o.items.map((i) => {
        const p = products.find((x) => x.id === i.id);
        return { name: p ? p.name : "Product #" + i.id, quantity: i.quantity };
      }),
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

// Contact message database mein save karo
app.post("/contact", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim();
    const message = String(req.body.message || "").trim();

    if (!name || !email || !message) {
      return res.status(400).json({ message: "Sab fields bharo" });
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      return res.status(400).json({ message: "Sahi email likho" });
    }

    if (name.length > 100 || email.length > 100 || message.length > 2000) {
      return res.status(400).json({ message: "Text bohat lamba hai" });
    }

    await Message.create({ name, email, message });
    res.json({ message: "Aap ka message mil gaya. Shukriya!" });
  } catch (err) {
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

// ---------------- ADMIN ----------------

// Ghalat password ki koshishon ka hisaab (har IP ka alag)
const loginTries = {};

// Admin login: password sahi ho to token do
app.post("/admin/login", (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const tries = loginTries[ip] || { count: 0, until: 0 };

  if (tries.until > now) {
    return res.status(429).json({ message: "Bohat ghalat koshishein. 10 minute baad try karo." });
  }

  const password = String(req.body.password || "");

  if (!sameText(password, ADMIN_PASSWORD)) {
    tries.count += 1;
    if (tries.count >= 5) {
      tries.until = now + 10 * 60 * 1000;
      tries.count = 0;
    }
    loginTries[ip] = tries;
    return res.status(400).json({ message: "Password galat hai" });
  }

  loginTries[ip] = { count: 0, until: 0 };
  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ token });
});

// Admin ke liye saare orders (product ke naam ke sath)
app.get("/admin/orders", adminAuth, async (req, res) => {
  try {
    const allOrders = await Order.find().sort({ date: -1 });

    const result = allOrders.map((o) => ({
      orderNumber: o.orderNumber,
      date: o.date,
      customerName: o.customerName,
      phone: o.phone,
      address: o.address,
      total: o.total,
      items: o.items.map((i) => {
        const p = products.find((x) => x.id === i.id);
        return { name: p ? p.name : "Product #" + i.id, quantity: i.quantity };
      }),
    }));

    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

// Admin ke liye saare contact messages
app.get("/admin/messages", adminAuth, async (req, res) => {
  try {
    const allMessages = await Message.find().sort({ date: -1 });
    res.json(allMessages);
  } catch (err) {
    res.status(500).json({ message: "Server mein masla aaya" });
  }
});

app.listen(PORT, () => console.log("Server " + PORT + " par chal raha hai"));