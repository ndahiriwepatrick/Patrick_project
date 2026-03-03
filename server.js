const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const path = require('path');
const db = require('./db');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({ 
    secret: 'secretkey123',
    resave: false, 
    saveUninitialized: false 
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
});

app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
    res.redirect('/signup.html');
});

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login.html');
}

function forwardAuthenticated(req, res, next) {
    if (!req.isAuthenticated()) return next();
    res.redirect('/dashboard.html');
}

passport.use(new LocalStrategy(
    { usernameField: 'email' },
    (email, password, done) => {
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {

            if (err) {
                console.log("Database error:", err);
                return done(err);
            }

            if (results.length === 0) {
                console.log("User not found");
                return done(null, false, { message: "User not found" });
            }

            const user = results[0];

            const match = await bcrypt.compare(password, user.password);

            if (!match) {
                console.log("Password incorrect");
                return done(null, false, { message: "Wrong password" });
            }

            console.log("Login successfuly");
            return done(null, user);
        });
    }
));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        if (err) return done(err);
        done(null, results[0]);
    });
});

app.get('/signup.html', forwardAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

app.get('/login.html', forwardAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/dashboard.html', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.post('/signup', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.send('Please fill all fields');
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) return res.send('Database error');

        if (results.length > 0) {
            return res.send('Email already exists');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            (err2) => {
                if (err2) return res.send('Error creating user');
                res.redirect('/login.html');
            }
        );
    });
});

app.post('/login', (req, res, next) => {

    passport.authenticate('local', (err, user, info) => {

        if (err) {
            return res.send("Error: " + err);
        }

        if (!user) {
            return res.send(info.message);
        }

        req.logIn(user, (err) => {
            if (err) return res.send("Login error");
            return res.redirect('/dashboard.html');
        });

    })(req, res, next);

});

app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) return res.redirect('/dashboard.html');
        res.redirect('/login.html');
    });
});

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});