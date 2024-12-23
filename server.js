const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const { generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB connection details
const mongoUri = "mongodb+srv://jaswanthuchiha69:pjkss17@cluster0.hpctd.mongodb.net/"; // Replace with your cluster info
let db, usersCollection;

// Connect to MongoDB
MongoClient.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(client => {
        db = client.db(); // Use the database
        usersCollection = db.collection("users"); // This is where you'll store user data
        console.log("Connected to MongoDB!");
    })
    .catch(err => {
        console.error("Error connecting to MongoDB:", err);
    });

// Middleware
app.use(bodyParser.json());

// POST: Register a new user (Fingerprint is captured as part of registration)
app.post('https://finger-print-v4py.onrender.com/register-user', async (req, res) => {
    const { username, credential } = req.body;

    try {
        const userDoc = {
            username,
            credential, // Store the credential (public key, etc.) for later use
            challenge: credential.response.clientDataJSON,  // Store the challenge for verification
        };

        await usersCollection.insertOne(userDoc); // Insert the user data into the MongoDB collection
        res.json({ success: true });
    } catch (err) {
        console.error("Error during registration:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// GET: Retrieve registration options (for the client to register a new fingerprint)
app.get('https://finger-print-v4py.onrender.com/get-register-options', (req, res) => {
    const options = generateRegistrationOptions({
        rpName: "MyApp",
        rpID: "example.com",
        userID: "user-id-1234", // Unique user ID from the frontend
        userName: "user@example.com", // Could be replaced with actual user data
        attestationType: "direct",
    });

    res.json({ publicKey: options });
});

// POST: Verify registration response (verify fingerprint)
app.post('https://finger-print-v4py.onrender.com/verify-registration', async (req, res) => {
    const { username, credential } = req.body;

    try {
        const user = await usersCollection.findOne({ username });

        if (!user) {
            return res.json({ success: false });
        }

        const verification = await verifyRegistrationResponse({
            credential,
            expectedChallenge: user.challenge,
            expectedOrigin: "https://example.com",
            expectedRPID: "example.com",
        });

        if (verification.verified) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    } catch (err) {
        console.error("Error during registration verification:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// GET: Retrieve login options (for fingerprint login)
app.get('https://finger-print-v4py.onrender.com/get-login-options', (req, res) => {
    const options = generateAuthenticationOptions({
        rpID: "example.com",
        userVerification: "required",  // This forces fingerprint authentication
    });

    res.json({ publicKey: options });
});

// POST: Verify login response (verify fingerprint during login)
app.post('https://finger-print-v4py.onrender.com/login-verify', async (req, res) => {
    const { username, credential } = req.body;

    try {
        const user = await usersCollection.findOne({ username });

        if (!user) {
            return res.json({ success: false });
        }

        const verification = await verifyAuthenticationResponse({
            credential,
            expectedChallenge: user.challenge,
            expectedOrigin: "https://example.com",
            expectedRPID: "example.com",
        });

        if (verification.verified) {
            res.json({ success: true });
        } else {
            res.json({ success: false });
        }
    } catch (err) {
        console.error("Error during login verification:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
