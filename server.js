const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(session({
    secret: 'diyaa_al_majd_secret_key_123',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // Session valid for 24 hours
}));

// Serve Static Files from 'public' folder
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup
const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) console.error('Error opening database:', err.message);
    else console.log('✅ Connected to SQLite database.');
});

// Initialize Database Tables & Default Admin Account
db.serialize(() => {
    // 1. Users Table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )`);

    // 2. Groups Table
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        allow_chat INTEGER DEFAULT 1
    )`);

    // 3. Group Members Table
    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        user_id INTEGER,
        is_group_admin INTEGER DEFAULT 0,
        PRIMARY KEY (group_id, user_id),
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // 4. Messages Table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER,
        user_id INTEGER,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Default Main Admin Setup (youssef / youssef1133)
    const defaultUser = 'youssef';
    const defaultPass = 'youssef1133';

    db.get(`SELECT * FROM users WHERE username = ?`, [defaultUser], async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash(defaultPass, 10);
            db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')`, [defaultUser, hash], (err) => {
                if (!err) console.log(`👑 Default Main Admin Created: ${defaultUser} / ${defaultPass}`);
            });
        }
    });
});

// Auth Middlewares
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.status(401).json({ success: false, error: 'المرجو تسجيل الدخول أولاً' });
}

function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).json({ success: false, error: 'غير مسموح! هذه الصلاحية خاصة بالأدمين فقط' });
}

// ------------------- AUTH ROUTES ------------------- //

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ success: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ success: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });

        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.json({ success: true, user: req.session.user });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Session Check
app.get('/api/session', (req, res) => {
    if (req.session.user) res.json({ loggedIn: true, user: req.session.user });
    else res.json({ loggedIn: false });
});

// ------------------- ADMIN DASHBOARD ROUTES ------------------- //

// Get Combined Admin Data (Users & Groups)
app.get('/api/admin/dashboard-data', isAuthenticated, isAdmin, (req, res) => {
    db.all(`SELECT id, username, role FROM users`, [], (err, users) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        
        db.all(`SELECT * FROM groups`, [], (err2, groups) => {
            if (err2) return res.status(500).json({ success: false, error: err2.message });
            res.json({ success: true, users, groups });
        });
    });
});

// Create User (Admin Only)
app.post('/api/admin/users', isAuthenticated, isAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, error: 'المرجو إدخال جميع البيانات' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (username, password, role) VALUES (?, ?, ?)`, [username, hashedPassword, role || 'user'], function(err) {
            if (err) return res.status(400).json({ success: false, error: 'اسم المستخدم مستعمل من قبل' });
            res.json({ success: true, message: 'تم إنشاء المستخدم بنجاح' });
        });
    } catch (err) {
        res.status(500).json({ success: false, error: 'خطأ أثناء التشفير' });
    }
});

// Delete User (Admin Only)
app.delete('/api/admin/users/:id', isAuthenticated, isAdmin, (req, res) => {
    const userId = req.params.id;
    
    db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, user) => {
        if (user && user.username === 'youssef') {
            return res.status(400).json({ success: false, error: 'لا يمكن حذف حساب الأدمين الرئيسي' });
        }
        
        db.run(`DELETE FROM users WHERE id = ?`, [userId], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, message: 'تم حذف المستخدم بنجاح' });
        });
    });
});

// Create Group (Admin Only)
app.post('/api/admin/groups', isAuthenticated, isAdmin, (req, res) => {
    const { name, allow_chat } = req.body;
    if (!name) return res.status(400).json({ success: false, error: 'أدخل اسم المجموعة' });

    db.run(`INSERT INTO groups (name, allow_chat) VALUES (?, ?)`, [name, allow_chat ? 1 : 0], function(err) {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: 'تم إنشاء المجموعة بنجاح', groupId: this.lastID });
    });
});

// Manage Group Members (Add User / Set Group Admin)
app.post('/api/admin/group-members', isAuthenticated, isAdmin, (req, res) => {
    const { group_id, user_id, is_group_admin } = req.body;
    db.run(`INSERT OR REPLACE INTO group_members (group_id, user_id, is_group_admin) VALUES (?, ?, ?)`, 
    [group_id, user_id, is_group_admin ? 1 : 0], (err) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: 'تم تحديث أعضاء المجموعة' });
    });
});

// Remove User From Group
app.delete('/api/admin/group-members', isAuthenticated, isAdmin, (req, res) => {
    const { group_id, user_id } = req.body;
    db.run(`DELETE FROM group_members WHERE group_id = ? AND user_id = ?`, [group_id, user_id], (err) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, message: 'تم إخراج المستخدم من المجموعة' });
    });
});

// ------------------- GROUPS & CHAT ROUTES ------------------- //

// Get Available Groups
app.get('/api/groups', isAuthenticated, (req, res) => {
    db.all(`SELECT * FROM groups`, [], (err, groups) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, groups });
    });
});

// Get Messages for Specific Group
app.get('/api/groups/:id/messages', isAuthenticated, (req, res) => {
    const groupId = req.params.id;
    db.all(`SELECT messages.*, users.username FROM messages 
            JOIN users ON messages.user_id = users.id 
            WHERE group_id = ? ORDER BY created_at ASC`, [groupId], (err, rows) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, messages: rows });
    });
});

// Post New Message to Group
app.post('/api/groups/:id/messages', isAuthenticated, (req, res) => {
    const groupId = req.params.id;
    const { message } = req.body;
    const userId = req.session.user.id;
    const userRole = req.session.user.role;

    // Check Chat Permission
    db.get(`SELECT allow_chat FROM groups WHERE id = ?`, [groupId], (err, group) => {
        if (!group) return res.status(404).json({ success: false, error: 'المجموعة غير موجودة' });

        if (group.allow_chat === 0 && userRole !== 'admin') {
            return res.status(403).json({ success: false, error: 'هذه المجموعة مخصصة للقراءة فقط من طرف الإدارة' });
        }

        db.run(`INSERT INTO messages (group_id, user_id, message) VALUES (?, ?, ?)`, [groupId, userId, message], function(err) {
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, messageId: this.lastID });
        });
    });
});

// Start Express Server
app.listen(PORT, () => {
    console.log(`===============================================`);
    console.log(`🚀 Diyaa Al Majd Backend Running on http://localhost:${PORT}`);
    console.log(`===============================================`);
});