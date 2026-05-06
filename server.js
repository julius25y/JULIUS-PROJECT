const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();

app.use(express.urlencoded({ extended: true }));

// SESSION SETUP
app.use(session({
    secret: "julius-secret-key",
    resave: false,
    saveUninitialized: false
}));

// DATABASE
const db = new sqlite3.Database("./users.db");

// create users table if not exists
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
`);

// HOME (LOGIN PAGE)
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/index.html");
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
            if (err) {
                return res.send("User already exists ❌ <a href='/register'>Try again</a>");
            }
            res.send("Account created ✔ <a href='/'>Login</a>");
        }
    );
});

// LOGIN USER
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (!user) {
            return res.send("User not found ❌ <a href='/'>Back</a>");
        }

        const match = await bcrypt.compare(password, user.password);

        if (match) {
            req.session.user = user.username;
            res.redirect("/dashboard");
        } else {
            res.send("Wrong password ❌ <a href='/'>Try again</a>");
        }
    });
});

// DASHBOARD (PROTECTED)
app.get("/dashboard", (req, res) => {
    if (!req.session.user) {
        return res.send("Access denied ❌ <a href='/'>Login</a>");
    }

    res.send(`
        <h1>Welcome ${req.session.user} 🚀</h1>
        <p>You are inside JULIUS PROJECT FULL SYSTEM</p>
        <a href="/logout">Logout</a>
    `);
});

// LOGOUT
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

// START SERVER
app.listen(3000, () => {
    console.log("JULIUS PROJECT FULL SYSTEM → http://localhost:3000");
});