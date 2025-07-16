import e from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import db from '../models/index.js';
const user = db.User;

const SECRET = process.env.JWT_SECRET;
/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: User registration and login
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name:
 *                 type: string
 *                 example: Bunny
 *               email:
 *                 type: string
 *                 example: Bunny@gmail.com
 *               password:
 *                 type: string
 *                 example: Bunny22
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Email already exists
 */
export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await user.findOne({ where: { email } });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await user.create({
      name,
      email,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "User registered",
      user: { id: newUser.id, email: newUser.email },
    });
  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
};
/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user and get JWT token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: Bunny@gmail.com
 *               password:
 *                 type: string
 *                 example: Bunny22
 *     responses:
 *       200:
 *         description: Successful login
 *       401:
 *         description: Invalid credentials
 *       404:
 *         description: User not found
 */
export const logIn = async (req,res) => {
    const {email, password} = req.body;

    const existingUser = await user.findOne({where: { email }});
    if(!existingUser) {
        return res.status(401).json({ message: "User not found"});
    }

    const validCredential = await bcrypt.compare(password, existingUser.password);
    if(!validCredential) {
        return res.status(401).json({ message: "Incorrect password."});
    }

    const token = jwt.sign({
            id: existingUser.id,
            email: existingUser.email
        }, SECRET, { expiresIn: '5h'}
    );

    res.json({token, user: {id: existingUser.id, email: existingUser.email}});
}
/**
 * @swagger
 * /auth/users:
 *   get:
 *     summary: Get all registered users (Protected)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *       401:
 *         description: Unauthorized (Missing or invalid token)
 */
export const getAllUsers = async (req, res) => {
  const users = await user.findAll({ attributes: ['id', 'name', 'email'] });
  res.json(users);
};