const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const server = express();
server.use(cors());
server.use(express.json());

// Create SQLite database connection
const db = new sqlite3.Database('carshowroom.db', (err) => {
    if (err) {
        console.error('Error connecting to database:', err);
    } else {
        console.log('Connected to database successfully');
    }
});

// Create users table
const create_users_table = `CREATE TABLE IF NOT EXISTS USERS
(ID INTEGER PRIMARY KEY AUTOINCREMENT, 
NAME TEXT NOT NULL, 
EMAIL TEXT UNIQUE NOT NULL, 
PASSWORD TEXT NOT NULL, 
USER_ROLE TEXT NOT NULL, 
ISADMIN INT)`;

db.run(create_users_table, (err) => {
    if (err) {
        console.error('Error creating users table:', err);
    } else {
        console.log('Users table created or already exists');
    }
});

// Registration endpoint
server.post('/user/register', (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    const user_role = req.body.user_role;

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).send('error hashing password');
        }
        const content = `INSERT INTO USERS (NAME,EMAIL,PASSWORD,USER_ROLE,ISADMIN) VALUES (?,?,?,?,?)`;
        db.run(content, [name, email, hashedPassword, user_role, 0], (err) => {
            if (err) {
                console.log(err.message);
                return res.status(401).send('Registration Failed');
            } else {
                return res.status(200).send('Registered Successfully');
            }
        });
    });
});

// Login endpoint
server.post('/user/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    const query = 'SELECT * FROM USERS WHERE EMAIL = ?';
    db.get(query, [email], (err, user) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        if (!user) {
            return res.status(401).send('User not found');
        }

        bcrypt.compare(password, user.PASSWORD, (err, match) => {
            if (err) {
                return res.status(500).send('Error comparing passwords');
            }
            if (!match) {
                return res.status(401).send('Invalid password');
            }
            return res.status(200).json({
                id: user.ID,
                name: user.NAME,
                email: user.EMAIL,
                user_role: user.USER_ROLE,
                admin: user.ISADMIN
            });
        });
    });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
