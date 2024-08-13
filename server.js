import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser'; // Import cookie-parser
import { Users } from './controllers/Users.js';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const users = new Users();

// Enable CORS for your frontend domain
app.use(cors({
    origin: 'http://localhost:8080', // Replace with your frontend URL
    credentials: true // Allow credentials (cookies) to be sent
}));

app.use(cookieParser()); // Use cookie-parser middleware
app.use(express.json()); // Middleware to parse JSON request bodies

// Define routes
app.get('/users', (req, res) => users.fetchUsers(req, res));
app.get('/users/:id', (req, res) => users.fetchUser(req, res));
app.post('/users', (req, res) => users.createUser(req, res));
app.put('/users/:id', (req, res) => users.updateUser(req, res));
app.delete('/users/:id', (req, res) => users.deleteUser(req, res));
app.post('/login', (req, res) => users.login(req, res));

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

console.log(process.env.DB_HOST); // Should print your database host
console.log(process.env.JWT_SECRET); // Should print your JWT secret
