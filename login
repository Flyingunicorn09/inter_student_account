// Import necessary libraries and modules
import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Define user interface
interface User {
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  email: string;
  password: string;
  isEmailVerified: boolean;
}

// In-memory database for storing user data
const users: User[] = [];

// Set up the Express app
const app = express();
app.use(bodyParser.json());

// Route: User Sign Up
app.post('/signup', (req: Request, res: Response) => {
  const { firstName, lastName, dateOfBirth, email, password } = req.body;

  // Check if user with the same email already exists
  const existingUser = users.find(user => user.email === email);
  if (existingUser) {
    return res.status(400).json({ error: 'User already exists with this email' });
  }

  // Generate a salt and hash the password
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return res.status(500).json({ error: 'Error while hashing the password' });
    }

    bcrypt.hash(password, salt, (err, hash) => {
      if (err) {
        return res.status(500).json({ error: 'Error while hashing the password' });
      }

      const newUser: User = {
        firstName,
        lastName,
        dateOfBirth,
        email,
        password: hash,
        isEmailVerified: false
      };

      // Add the new user to the database
      users.push(newUser);

      // Send email verification link (implementation not included)

      return res.status(201).json({ message: 'User created successfully' });
    });
  });
});

// Route: User Sign In
app.post('/signin', (req: Request, res: Response) => {
  const { email, password } = req.body;

  // Check if user with the provided email exists
  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  // Compare the provided password with the stored hash
  bcrypt.compare(password, user.password, (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error while comparing passwords' });
    }

    if (!result) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate and sign a JWT token
    const token = jwt.sign({ email: user.email }, 'secretKey', { expiresIn: '1h' });

    return res.status(200).json({ token });
  });
});

// Middleware: Verify JWT token
function verifyToken(req: Request, res: Response, next: any) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }

  jwt.verify(token, 'secretKey', (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Attach the decoded token to the request object
    req.body.user = decoded;

    next();
  });
}

// Route: Personal Details Page
app.get('/details', verifyToken, (req: Request, res: Response