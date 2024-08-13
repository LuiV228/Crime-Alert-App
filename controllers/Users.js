import { connection as db } from "../config/index.js";
import { hash, compare } from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config(); // Ensure environment variables are loaded

class Users {
    fetchUsers(req, res) {
        const qry = `
        SELECT UserId, Name, Surname, Email, contact, UserRole
        FROM Users;
        `;
        db.query(qry, (err, results) => {
            if (err) throw err;
            res.json({
                status: res.statusCode,
                results
            });
        });
    }

    fetchUser(req, res) {
        const qry = `
        SELECT UserID, Name, Surname, Email, contact, UserRole
        FROM Users
        WHERE userID = ?;
        `;
        db.query(qry, [req.params.id], (err, result) => {
            if (err) throw err;
            res.json({
                status: res.statusCode,
                result: result[0]
            });
        });
    }

    async createUser(req, res) {
        let data = req.body;

        // Hash the password before storing
        data.userPassword = await hash(data.userPassword, 8);

        const qry = `
            INSERT INTO Users (Name, Surname, Email, contact, UserRole, userPassword)
            VALUES (?, ?, ?, ?, ?, ?);
        `;
        
        db.query(qry, [data.Name, data.Surname, data.Email, data.contact, data.UserRole, data.userPassword], (err) => {
            if (err) {
                return res.json({
                    status: res.statusCode,
                    msg: "This email address is already in use or there was another error."
                });
            }
            res.json({
                status: res.statusCode,
                msg: "You're registered successfully"
            });
        });
    }

    async deleteUser(req, res) {
        const qry = `
        DELETE FROM Users
        WHERE userID = ?;
        `;
        db.query(qry, [req.params.id], (err) => {
            if (err) throw err;
            res.json({
                status: res.statusCode,
                msg: "This User was deleted"
            });
        });
    }

    async updateUser(req, res) {
        const data = req.body;
        if (data?.userPassword) {
            data.userPassword = await hash(data?.userPassword, 8);
        }
        const qry = `
        UPDATE Users
        SET ?
        WHERE userID = ${req.params.id};
        `;
        db.query(qry, [data], (err) => {
            if (err) throw err;
            res.json({
                status: res.statusCode,
                msg: "This user was updated"
            });
        });
    }

    login(req, res) {
        const { Email, userPassword } = req.body;
        const qry = `
        SELECT userID, Name, Surname, Email, userPassword, contact, UserRole
        FROM Users
        WHERE Email = ?;
        `;
        db.query(qry, [Email], async (err, result) => {
            if (err) throw err;
            if (!result?.length) {
                res.status(401).json({
                    status: res.statusCode,
                    msg: "Wrong email address provided"
                });
            } else {
                const validPass = await compare(userPassword, result[0].userPassword);
                if (validPass) {
                    const token = createToken({
                        userID: result[0].userID,
                        Email,
                        userRole: result[0].UserRole
                    });

                    // Set the token in a cookie
                    res.cookie('authToken', token, {
                        httpOnly: true,     // Ensure the cookie is only accessible by the web server
                        secure: process.env.NODE_ENV === 'production',  // Set to true if using HTTPS
                        sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Lax',  // Allow cross-site cookies in production
                        maxAge: 60 * 60 * 1000,  // 1 hour
                        path: '/' // Ensure path is set
                    });

                    res.json({
                        status: res.statusCode,
                        msg: "You're logged in",
                        token,
                        result: result[0]
                    });
                } else {
                    res.status(401).json({
                        status: res.statusCode,
                        msg: "Please provide the correct password"
                    });
                }
            }
        });
    }
}

const createToken = (user) => {
    return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "1h" });
};

export { Users };


