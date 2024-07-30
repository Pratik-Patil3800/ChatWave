const express = require("express");
const router = express.Router();
const pool = require('../db');
require("dotenv").config();

router.post('/signup', async (req, res) => {
    try {
        const potentialLogin = await pool.query(
            "SELECT id, username, passhash, userid FROM users u WHERE u.username=$1",
            [req.body.username]
        );
        console.log("potentialLogin:", potentialLogin.rows);
        if (potentialLogin.rows.length > 0) {
            res.status(400).json("user already present");
        } else {
            const hashedPass = await bcrypt.hash(req.body.password, 10);
            const newUserQuery = await pool.query(
              "INSERT INTO users(username, passhash, userid) values($1,$2,$3) RETURNING id, username, userid",
              [req.body.username, hashedPass, uuidv4()]
            );
            res.status(200).json({ message: "registered" });
        }
    } catch (err) {
        console.error("Database query error:", err.stack);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.post('/login', async (req, res) => {
    try {
        const potentialLogin = await pool.query(
            "SELECT id, username, passhash, userid FROM users u WHERE u.username=$1",
            [req.body.mail]
        );
        if (potentialLogin.rows.length > 0) {
            const isSamePass = await bcrypt.compare(
                req.body.password,
                potentialLogin.rows[0].passhash
              );
           if(isSamePass){
            const tokenData = {
                mail: req.body.username,
                id: potentialLogin.rows[0].id,
                userid: potentialLogin.rows[0].userid,
            }
            const token = await jwt.sign(tokenData, process.env.TOKEN_SECRET, {expiresIn: "1d"})
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production', 
                sameSite: 'Strict', 
                maxAge: 24 * 60 * 60 * 1000 
            });
           }
           else{
            res.status(200).json({ message: "Credentials does not match" });
           }
            
            
        } else {
            res.status(400).json("user not found");
        }
    } catch (err) {
        console.error("Database query error:", err.stack);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

module.exports = router;
