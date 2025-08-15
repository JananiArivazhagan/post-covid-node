require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cors = require('cors');
//const fetch = require('node-fetch');

// Read from environment variables
const FLASK_URL = process.env.FLASK_URL || 'http://127.0.0.1:8000/predict';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';

const app = express();
const port = process.env.PORT || 3000;
//const port = 3000; // Or your preferred port

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded
app.use(express.json());

app.use(express.static(__dirname)); // Serve static files (HTML, CSS, JS)
//app.use(express.static(path.join(__dirname)));  // Serve everything from post-covid/
app.use(cors({
    //For deployment
    
    origin: 'FRONTEND_ORIGIN',
    /*origin: 'http://localhost:8000', // Adjust if your frontend is on a different URL*/
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    allowedHeaders: 'Content-Type, Authorization'
  }));

const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the users database.');

    db.run(`CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        phone TEXT UNIQUE,
        password TEXT
        
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS health_profiles (
        user_id INTEGER PRIMARY KEY,
        age INTEGER,
        gender INTEGER,
        covid_affected INTEGER,
        covid_vaccine INTEGER,
        vaccine_doses INTEGER,
        has_allergy INTEGER DEFAULT 0,
        allergy_dust INTEGER DEFAULT 0,
        allergy_pollen INTEGER DEFAULT 0,
        allergy_other TEXT,
        has_heart_problem INTEGER DEFAULT 0,
        has_diabetes INTEGER DEFAULT 0,
        medical_history_other TEXT,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        expiry DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS symptom_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        fever INTEGER,
        shortness_of_breath INTEGER,
        sore_throat INTEGER,
        runny_nose INTEGER,
        dizziness INTEGER,
        smell_loss INTEGER,
        taste_loss INTEGER,
        mood_loss INTEGER,
        appetite_loss INTEGER,
        chest_palpitations INTEGER,
        joint_pain INTEGER,
        muscle_pain INTEGER,
        insomia INTEGER,
        anxiety INTEGER,
        tiredness INTEGER,
        log_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        timestamp DATETIME DEFAULT (DATETIME('now', 'localtime')),
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )`);

    // Safely add isAdmin column only if it doesn't exist
db.get("PRAGMA table_info(users);", (err, row) => {
    if (err) {
        console.error("Error checking table info:", err);
    } else {
        db.all("PRAGMA table_info(users);", (err, columns) => {
            if (!columns.some(col => col.name === "isAdmin")) {
                db.run("ALTER TABLE users ADD COLUMN isAdmin INTEGER DEFAULT 0;");
                console.log("isAdmin column added.");
            } else {
                console.log("isAdmin column already exists.");
            }
        });
    }
});

    
});

//predict route
app.post('/predict', async (req, res) => {
    console.log('Received prediction request from frontend:', req.body);
    const symptomData = req.body;
  
    try {
      //for deployment
      
      //const flaskUrl = 'http://127.0.0.1:8000/predict';
      console.log(`Node.js is sending request to: ${flaskUrl}`);
  
      const flaskPredictionResponse = await fetch(FLASK_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(symptomData),
      });
  
      console.log('Node.js received response from Flask:', flaskPredictionResponse.status);
  
      if (!flaskPredictionResponse.ok) {
        let errorText = '';
        try {
          errorText = await flaskPredictionResponse.text();
        } catch (e) {
          errorText = `Failed to read error text from Flask: ${e}`;
        }
        console.error('Error from Flask:', flaskPredictionResponse.status, errorText);
        return res.status(flaskPredictionResponse.status).json({ error: `Flask prediction failed: ${errorText}` });
      }
  
      const predictionResult = await flaskPredictionResponse.json();
      console.log('Prediction from Flask:', predictionResult);
      res.json(predictionResult);
  
    } catch (error) {
      console.error('Error communicating with Flask:', error);
      res.status(500).json({ error: 'Failed to communicate with the prediction service.' });
    }
  });

  //last added route
  app.post('/api/proxy-to-flask', async (req, res) => {
      try {
        const flaskRes = await fetch(FLASK_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req.body)
        });
    
        const flaskData = await flaskRes.json();
        res.json(flaskData);
      } catch (err) {
        console.error('Error communicating with Flask:', err);
        res.status(500).json({ error: 'Failed to communicate with the prediction service.' });
      }
    });

// API endpoint to get weekly symptom data for a user
// API endpoint to get weekly symptom data for a user
app.get('/api/weekly-symptoms/:userId', (req, res) => {
    const userId = req.params.userId;
    // Calculate date for one week ago
    // Using UTC date for comparison to avoid timezone issues, though still depends on local server time if not careful
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');

    db.all(`
        SELECT
            fever, shortness_of_breath, sore_throat, runny_nose,
            dizziness, smell_loss, taste_loss, mood_loss, appetite_loss,
            chest_palpitations, joint_pain, muscle_pain, insomia, anxiety, tiredness,
            log_timestamp
        FROM symptom_logs
        WHERE user_id = ? AND log_timestamp >= ?
        ORDER BY log_timestamp ASC
    `, [userId, oneWeekAgo], (err, rows) => {
        if (err) {
            console.error('Error fetching weekly symptom data:', err.message);
            return res.status(500).json({ error: 'Failed to fetch weekly symptom data.' });
        }
        // It's possible a user has no logs in the last week
        // We'll still try to send their profile data if logs are absent.

        // Aggregate symptoms (e.g., average over the week, or latest entry)
        const aggregatedSymptoms = {
            fever: 0, shortness_of_breath: 0, sore_throat: 0, runny_nose: 0,
            dizziness: 0, smell_loss: 0, taste_loss: 0, mood_loss: 0, appetite_loss: 0,
            chest_palpitations: 0, joint_pain: 0, muscle_pain: 0, insomia: 0, anxiety: 0, tiredness: 0
        };

        if (rows.length > 0) {
            const symptomKeys = ['fever', 'shortness_of_breath', 'sore_throat', 'runny_nose', 'dizziness', 'smell_loss', 'taste_loss', 'mood_loss', 'appetite_loss', 'chest_palpitations', 'joint_pain', 'muscle_pain', 'insomia', 'anxiety', 'tiredness'];
            
            rows.forEach(log => {
                symptomKeys.forEach(key => {
                    aggregatedSymptoms[key] += log[key];
                });
            });

            symptomKeys.forEach(key => {
                // Calculate average and round to nearest integer
                aggregatedSymptoms[key] = Math.round(aggregatedSymptoms[key] / rows.length); 
            });
        }
        
        // Always fetch user's basic health profile for the report, even if no symptoms
        db.get(`
            SELECT
                u.name,
                hp.age,
                hp.gender,
                hp.covid_affected,
                hp.covid_vaccine AS vaccinations_taken,
                hp.vaccine_doses AS no_of_doses_taken,
                hp.has_allergy AS allergy,
                CASE
                    WHEN hp.has_heart_problem = 1 OR hp.has_diabetes = 1 OR hp.medical_history_other IS NOT NULL
                    THEN 1 ELSE 0
                END AS medical_history
            FROM users u
            LEFT JOIN health_profiles hp ON u.user_id = hp.user_id
            WHERE u.user_id = ?
        `, [userId], (profileErr, profileRow) => {
            if (profileErr) {
                console.error('Error fetching user profile for report:', profileErr.message);
                return res.status(500).json({ error: 'Failed to fetch user profile for report.' });
            }
            if (!profileRow) {
                // This scenario means the user_id exists in 'users' but not 'health_profiles'
                // Or user_id itself doesn't exist.
                return res.status(404).json({ error: 'User profile not found for report generation.' });
            }

            // Construct the report data, merging profile and aggregated symptoms
            const reportData = {
                name: profileRow.name || 'N/A', // Handle case where name might be null if not set
                Age: profileRow.age || 'N/A',
                Gender: profileRow.gender || 'N/A',
                Covid_affected: profileRow.covid_affected !== null ? profileRow.covid_affected : 'N/A',
                Vaccinations_taken: profileRow.vaccinations_taken || 'N/A',
                No_of_doses_taken: profileRow.no_of_doses_taken !== null ? profileRow.no_of_doses_taken : 'N/A',
                Allergy: profileRow.allergy !== null ? profileRow.allergy : 'N/A',
                Medical_history: profileRow.medical_history !== null ? profileRow.medical_history : 'N/A',
                ...aggregatedSymptoms // Spread the aggregated symptoms
            };
            res.json(reportData);
        });
    });
});

// API endpoint to get daily symptom data for a user for a given period
// ... (rest of your server.js code) ...

app.get('/api/daily-symptoms/:userId', (req, res) => {
    const userId = req.params.userId;
    const days = req.query.days || 7; // This line is no longer needed if fetching all data

    // Ensure a valid userId is provided
    if (!userId || isNaN(userId)) {
        return res.status(400).json({ error: 'Invalid User ID provided.' });
    }

    const sinceDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace('T', ' ');

    // Modified Query: Fetch ALL symptom logs for the user, ordered by date
    db.all(
        `SELECT
            
            DATE(log_timestamp) as log_date,
            fever,
            shortness_of_breath,
            sore_throat,
            runny_nose,
            dizziness,
            smell_loss,
            taste_loss,
            mood_loss,
            appetite_loss,
            chest_palpitations,
            joint_pain,
            muscle_pain,
            insomia,
            anxiety,
            tiredness
         FROM symptom_logs
         WHERE user_id = ? AND log_timestamp >= ?
         ORDER BY log_date ASC`, // Order by date to ensure proper chart display
        [userId,sinceDate], // Only userId is needed for the query
        (err, rows) => {
            if (err) {
                console.error('Error fetching daily symptom data:', err.message);
                return res.status(500).json({ error: 'Failed to fetch daily symptom data.' });
            }
            if (rows.length === 0) {
                return res.status(404).json({ message: 'No symptom logs found for this user.' }); // Updated message
            }
            res.json(rows);
        }
    );
});

// ... (rest of your server.js code) ...

// Registration Route
app.post('/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
        'INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
        [name, email, phone, hashedPassword],
        function (err) {
            if (err) {
                console.log("database insertion error:", err);
                if (err.message.includes('UNIQUE constraint failed: users.email')) {
                    return res.status(409).json({ error: 'This email address is already registered.' });
                } else if (err.message.includes('UNIQUE constraint failed: users.phone')) {
                    return res.status(409).json({ error: 'This phone number is already registered.' });
                }
                return res.status(500).json({ error: 'An error occurred during registration.' });
            }
            console.log("registration success, user id:", this.lastID);
            res.json({ message: 'Registration successful', redirect: `/health-profile.html?userId=${this.lastID}`, userId: this.lastID });
        }
    );
});

// Route to handle submission of health profile data
app.post('/submit-health-profile', (req, res) => {
    const { userId, age, gender, covid_affected, covid_vaccine, vaccine_doses, has_allergy, allergy_dust, allergy_pollen, allergy_other, has_heart_problem, has_diabetes, medical_history_other } = req.body;

    const allergyInt = has_allergy === '1' ? 1 : 0;
    const allergyDustInt = allergy_dust === '1' ? 1 : 0;
    const allergyPollenInt = allergy_pollen === '1' ? 1 : 0;
    const heartProblemInt = has_heart_problem === '1' ? 1 : 0;
    const diabetesInt = has_diabetes === '1' ? 1 : 0;
    const covidAffectedInt = covid_affected === '1' ? 1 : 0;
    const covidVaccineInt = covid_vaccine === '1' ? 1 : 0;
    const doses = covidVaccineInt === 1 ? parseInt(vaccine_doses) : 0;

    db.run(
        `INSERT INTO health_profiles (user_id, age, gender, covid_affected, covid_vaccine, vaccine_doses, has_allergy, allergy_dust, allergy_pollen, allergy_other, has_heart_problem, has_diabetes, medical_history_other)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
            age = ?,
            gender = ?,
            covid_affected = ?,
            covid_vaccine = ?,
            vaccine_doses = ?,
            has_allergy = ?,
            allergy_dust = ?,
            allergy_pollen = ?,
            allergy_other = ?,
            has_heart_problem = ?,
            has_diabetes = ?,
            medical_history_other = ?`,
        [parseInt(userId), parseInt(age), parseInt(gender), covidAffectedInt, covidVaccineInt, doses, allergyInt, allergyDustInt, allergyPollenInt, allergy_other, heartProblemInt, diabetesInt, medical_history_other,
         parseInt(age), parseInt(gender), covidAffectedInt, covidVaccineInt, doses, allergyInt, allergyDustInt, allergyPollenInt, allergy_other, heartProblemInt, diabetesInt, medical_history_other],
        function (err) {
            if (err) {
                console.error("Error saving health profile:", err.message);
                return res.status(500).json({ error: 'Failed to save health profile.' });
            }
            res.json({ message: 'Health profile updated successfully', redirect: '/login.html' });
        }
    );
});

// Login Route
app.post('/login', (req, res) => {
    const { identifier, password } = req.body;

    db.get('SELECT user_id, name, password, isAdmin FROM users WHERE email = ? OR phone = ?', [identifier, identifier], async (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const passwordMatch = await bcrypt.compare(password, row.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

         // ✅ Password matches, send response including admin flag
        return res.status(200).json({
            message: 'Login successful',
            //email: row.email,
            isAdmin: row.isAdmin,  // this comes from the DB
            userId: row.user_id,
            userName: row.name
        });
    
        //res.json({ message: 'Login successful', userId: row.user_id, userName: row.name, redirect: '/dashboard.html' });
    });
    
});

// Forgot Password Route
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    db.get('SELECT user_id FROM users WHERE email = ?', [email], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!row) {
            return res.json({ message: 'If your email exists, a reset link has been sent.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        console.log("Generated reset token:", resetToken);
        const expiryTime = new Date(Date.now() + 3600000).toISOString().slice(0, 19).replace('T', ' ');

        db.run('INSERT INTO password_reset_tokens (token, user_id, expiry) VALUES (?, ?, ?)', [resetToken, row.user_id, expiryTime], function(err) {
            if (err) {
                console.error("Error storing reset token:", err);
                return res.status(500).json({ error: 'Failed to generate reset link.' });
            }

            //for deployment
            const BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${port}`;
            const resetLink = `${BASE_URL}/reset-password.html?token=${resetToken}`;

            //const resetLink = `http://localhost:${port}/reset-password.html?token=${resetToken}`; // Adjust domain and port if needed

            const transporter = nodemailer.createTransport({
                service: process.env.EMAIL_SERVICE,
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset Request',
                html: `<p>You have requested a password reset. Click the following link to reset your password:</p><a href="${resetLink}">${resetLink}</a><p>This link will expire in 1 hour.</p>`
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error("Error sending reset email:", error);
                    return res.status(500).json({ error: 'Failed to send reset email.' });
                }
                console.log('Reset email sent:', info.response);
                res.json({ message: 'If your email exists, a reset link has been sent.' });
            });
        });
    });
});


//admin route

app.get('/admin/users', (req, res) => {
  db.all("SELECT user_id, email, isAdmin FROM users", [], (err, rows) => { // Include user_id here
    if (err) return res.status(500).json({ error: err.message });
    res.json({ users: rows });
  });
});

app.post('/admin/delete', (req, res) => {
  const { email } = req.body;
  db.run("DELETE FROM users WHERE email = ?", [email], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'User deleted' });
  });
});

// New Admin API Endpoints for viewing user data
app.get('/admin/user-personal-info/:userId', (req, res) => {
    const userId = req.params.userId;
    db.get('SELECT name, email, phone FROM users WHERE user_id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Error fetching user personal info:', err.message);
            return res.status(500).json({ error: 'Failed to fetch user personal information.' });
        }
        if (!row) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.json(row);
    });
});

app.get('/admin/user-health-profile/:userId', (req, res) => {
    const userId = req.params.userId;
    db.get(`
        SELECT
            age, gender, covid_affected, covid_vaccine, vaccine_doses,
            has_allergy, allergy_dust, allergy_pollen, allergy_other,
            has_heart_problem, has_diabetes, medical_history_other
        FROM health_profiles
        WHERE user_id = ?
    `, [userId], (err, row) => {
        if (err) {
            console.error('Error fetching user health profile:', err.message);
            return res.status(500).json({ error: 'Failed to fetch user health profile.' });
        }
        if (!row) {
            return res.status(404).json({ error: 'Health profile not found for this user.' });
        }
        res.json(row);
    });
});

app.get('/admin/user-symptom-logs/:userId', (req, res) => {
    const userId = req.params.userId;
    db.all(`
        SELECT
            log_timestamp, fever, shortness_of_breath, sore_throat, runny_nose,
            dizziness, smell_loss, taste_loss, mood_loss, appetite_loss,
            chest_palpitations, joint_pain, muscle_pain, insomia, anxiety, tiredness
        FROM symptom_logs
        WHERE user_id = ?
        ORDER BY log_timestamp DESC
    `, [userId], (err, rows) => {
        if (err) {
            console.error('Error fetching user symptom logs:', err.message);
            return res.status(500).json({ error: 'Failed to fetch user symptom logs.' });
        }
        if (rows.length === 0) {
            return res.status(404).json({ message: 'No symptom logs found for this user.' });
        }
        res.json(rows);
    });
});
//admin route end

// Reset Password Route


app.post('/reset-password', async (req, res) => {
    console.log("--- /reset-password route hit ---");

    const { token, newPassword, confirmPassword } = req.body;

    console.log("Received reset request with token:", token);
    console.log("Received newPassword:", newPassword);
    console.log("Received confirmPassword:", confirmPassword);

    // Validate passwords
    if (newPassword !== confirmPassword) {
        console.log("Error: Passwords do not match.");
        return res.status(400).json({ error: 'Passwords do not match.' });
    }

    // Fetch token from SQLite
    const sql = `SELECT user_id FROM password_reset_tokens 
                 WHERE LOWER(token) = LOWER(?) 
                 AND expiry > DATETIME('now')`;

    db.get(sql, [token], async (err, row) => {
        if (err) {
            console.error("Database error checking token:", err.message);
            return res.status(500).json({ error: 'Database error.' });
        }

        console.log("Token lookup result:", row);

        if (!row) {
            console.log("Error: Invalid or expired reset token.");
            return res.status(400).json({ error: 'Invalid or expired reset token.' });
        }

        try {
            // Hash new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            console.log("Hashed new password");

            // Update user password
            db.run('UPDATE users SET password = ? WHERE user_id = ?', [hashedPassword, row.user_id], function(err) {
                if (err) {
                    console.error("Database error updating password:", err.message);
                    return res.status(500).json({ error: 'Failed to update password.' });
                }

                console.log("Password updated for user:", row.user_id);

                // Delete used token
                db.run('DELETE FROM password_reset_tokens WHERE token = ?', [token], (deleteErr) => {
                    if (deleteErr) {
                        console.error("Error deleting reset token:", deleteErr.message);
                        // Even if delete fails, send success for password update
                        return res.status(200).json({ message: 'Password reset successful, but token not deleted.' });
                    }

                    console.log("Reset token deleted:", token);
                    res.json({
                        message: 'Password reset successful. You can now log in with your new password.',
                        redirect: '/login.html'
                    });
                });
            });

        } catch (e) {
            console.error("Error hashing password:", e.message);
            res.status(500).json({ error: 'Error resetting password.' });
        }
    });
});

// API endpoint to get user details (returns age, gender, covid_affected)
app.get('/api/user-details/:userId', (req, res) => {
    const userId = req.params.userId;

    db.get(`
        SELECT
            hp.age,
            hp.gender,
            hp.covid_affected,
            hp.covid_vaccine AS vaccinations_taken,
            hp.vaccine_doses AS no_of_doses_taken,
            hp.has_allergy AS allergy,
            CASE 
                WHEN hp.has_heart_problem = 1 OR hp.has_diabetes = 1 OR hp.medical_history_other IS NOT NULL 
                THEN 1 ELSE 0 
            END AS medical_history
        FROM health_profiles hp
        WHERE hp.user_id = ?
    `, [userId], (err, row) => {
        if (err) {
            console.error('Error fetching user details:', err.message);
            return res.status(500).json({ error: 'Failed to fetch user details.' });
        }
        if (!row) {
            return res.status(404).json({ error: 'User details not found.' });
        }
        res.json(row);
    });
});


app.post('/api/log-symptoms', (req, res) => {
    const { userId, fever, shortness_of_breath, sore_throat, runny_nose, dizziness, smell_loss, taste_loss, mood_loss, appetite_loss, chest_palpitations, joint_pain, muscle_pain, insomia, anxiety, tiredness } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required to log symptoms.' });
    }

    db.run(
        `INSERT INTO symptom_logs (user_id, fever, shortness_of_breath, sore_throat, runny_nose, dizziness, smell_loss, taste_loss, mood_loss, appetite_loss, chest_palpitations, joint_pain, muscle_pain, insomia, anxiety, tiredness)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [userId, fever, shortness_of_breath, sore_throat, runny_nose, dizziness, smell_loss, taste_loss, mood_loss, appetite_loss, chest_palpitations, joint_pain, muscle_pain, insomia, anxiety, tiredness],
        function (err) {
            if (err) {
                console.error('Error logging symptoms:', err.message);
                return res.status(500).json({ error: 'Failed to log symptoms.' });
            }
            console.log(`Symptoms logged for user ${userId} with log ID: ${this.lastID}`);
            res.json({ message: 'Symptoms logged successfully.' });
        }
    );
});

//calendar route
app.get('/api/symptom-logs/:userId', (req, res) => {
  db.all(
    `SELECT log_timestamp FROM symptom_logs WHERE user_id = ?`,
    [req.params.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch logs' });

      console.log("🗄️ Fetched raw timestamps:", rows);
      const dates = rows
        .map(r => r.log_timestamp)
        .filter(Boolean); // remove nulls

      res.json({ dates });
    }
  );
});



app.listen(port, () => console.log(`Server running on port ${port}`));