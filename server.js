const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

/* =========================
   MIDDLEWARE
========================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.use(session({
    secret: "julius-secret-key",
    resave: false,
    saveUninitialized: false
}));

/* =========================
   DATABASE
========================= */
const db = new sqlite3.Database("./users.db");

db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
`);

/* =========================
   ROUTES
========================= */

// HOME
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

// REGISTER PAGE
app.get("/register", (req, res) => {
    res.send(`
        <h2>Register Account</h2>
        <form method="POST" action="/register">
            <input name="username" placeholder="Username" required />
            <br><br>
            <input type="password" name="password" placeholder="Password" required />
            <br><br>
            <button>Register</button>
        </form>
        <br>
        <a href="/">Back to Login</a>
    `);
});

// REGISTER USER
app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashed],
        (err) => {
            if (err) return res.send("User already exists ❌ <a href='/register'>Back</a>");
            res.send("Account created ✔ <a href='/'>Login</a>");
        }
    );
});

// LOGIN
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (!user) return res.send("User not found ❌ <a href='/'>Back</a>");

        const match = await bcrypt.compare(password, user.password);

        if (match) {
            req.session.user = user.username;

            // 🔥 ADMIN CHECK
            if (user.username === "admin") {
                return res.redirect("/admin");
            }

            return res.redirect("/dashboard");
        } else {
            res.send("Wrong password ❌ <a href='/'>Try again</a>");
        }
    });
});

/* =========================
   USER DASHBOARD
========================= */
app.get("/dashboard", (req, res) => {
    if (!req.session.user) {
        return res.send("Access denied ❌ <a href='/'>Login</a>");
    }

    res.send(`
        <h1>User Dashboard 🚀</h1>
        <p>Welcome ${req.session.user}</p>
        <a href="/logout">Logout</a>
    `);
});

/* =========================
   ADMIN DASHBOARD (NEW)
========================= */
app.get("/admin", (req, res) => {
    if (!req.session.user || req.session.user !== "admin") {
        return res.send("Access denied ❌ Admin only");
    }

    db.all("SELECT id, username FROM users", [], (err, rows) => {
        if (err) return res.send("Database error ❌");

        let userList = rows.map(u => `<li>${u.id} - ${u.username}</li>`).join("");

        res.send(`
            <h1>🔥 ADMIN DASHBOARD</h1>
            <p>Welcome Boss: ${req.session.user}</p>

            <h3>All Users:</h3>
            <ul>${userList}</ul>

            <br>
            <a href="/dashboard">User Dashboard</a>
            <br>
            <a href="/logout">Logout</a>
        `);
    });
});

/* =========================
   LOGOUT
========================= */
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

/* =========================
   START SERVER
========================= */
app.listen(3000, () => {
    console.log("JULIUS PROJECT FULL SYSTEM → http://localhost:3000");
});