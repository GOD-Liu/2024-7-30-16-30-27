const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const helmet = require('helmet');
const app = express();
const upload = multer();

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public', {
    maxAge: '1d',
    etag: false
}));

// Database initialization
const db = new sqlite3.Database(path.join(__dirname, 'submissions.db'));

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        organization TEXT NOT NULL,
        carPlate TEXT NOT NULL,
        signature TEXT NOT NULL,
        submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        organization TEXT NOT NULL
    )`);
});

// Middleware for authentication
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send('Unauthorized');
    }

    const token = authHeader.split(' ')[1];
    const [username, password] = Buffer.from(token, 'base64').toString().split(':');
    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, user) => {
        if (err || !user) {
            return res.status(401).send('Unauthorized');
        }
        req.user = user;
        next();
    });
}

// Submission routes
app.post('/api/submit', upload.none(), (req, res) => {
    const { name, phone, organization, carPlate, signature } = req.body;

    if (!name || !phone || !organization || !carPlate || !signature) {
        return res.status(400).send('All fields are required.');
    }

    const phonePattern = /^\d{11}$/;
    const carPlatePattern = /^[\u4e00-\u9fa5]{1}[A-Z]{1}[\dA-Z]{5}$/;

    if (!phonePattern.test(phone)) {
        return res.status(400).send('Invalid phone number format.');
    }

    if (!carPlatePattern.test(carPlate)) {
        return res.status(400).send('Invalid car plate format.');
    }

    db.run(`INSERT INTO submissions (name, phone, organization, carPlate, signature) VALUES (?, ?, ?, ?, ?)`,
        [name, phone, organization, carPlate, signature], function (err) {
            if (err) {
                console.error('Database write failed', err);
                return res.status(500).send('Submission failed.');
            }
            res.status(200).send('Submission successful.');
        });
});

// Get all submissions
app.get('/api/submissions', authenticate, (req, res) => {
    let query = `SELECT * FROM submissions WHERE organization = ?`;
    const params = [req.user.organization];

    if (req.query.date) {
        query += ` AND date(submitted_at) = date(?)`;
        params.push(req.query.date);
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).send('Could not retrieve data.');
        }
        res.json(rows);
    });
});

// Delete a submission
app.delete('/api/submissions/:id', authenticate, (req, res) => {
    db.run(`DELETE FROM submissions WHERE id = ? AND organization = ?`, [req.params.id, req.user.organization], function (err) {
        if (err || this.changes === 0) {
            return res.status(500).send('Delete failed.');
        }
        res.status(200).send('Delete successful.');
    });
});

// Download all submissions as CSV
app.get('/api/download', authenticate, (req, res) => {
    db.all(`SELECT * FROM submissions WHERE organization = ?`, [req.user.organization], (err, rows) => {
        if (err) {
            return res.status(500).send('Could not download data.');
        }

        let csv = 'ID,Name,Phone,Organization,Car Plate,Signature,Submitted At\n';
        rows.forEach(row => {
            csv += `${row.id},${row.name},${row.phone},${row.organization},${row.carPlate},${row.signature},${row.submitted_at}\n`;
        });

        res.header('Content-Type', 'text/csv');
        res.attachment('submissions.csv');
        res.send(csv);
    });
});

// User management routes
app.post('/api/users', authenticate, (req, res) => {
    if (req.user.organization !== 'admin') {
        return res.status(403).send('Permission denied.');
    }
    const { username, password, organization } = req.body;
    db.run(`INSERT INTO users (username, password, organization) VALUES (?, ?, ?)`, [username, password, organization], function (err) {
        if (err) {
            return res.status(500).send('User creation failed.');
        }
        res.status(201).send('User created successfully.');
    });
});

// Server listen
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
