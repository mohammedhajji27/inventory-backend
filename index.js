import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const prisma = new PrismaClient();

app.use(cors({
  origin: [
    'http://localhost:5173',
    process.env.FRONTEND_URL || ''
  ].filter(Boolean),
  credentials: true
}));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

// -- Authentication Middleware --
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (!token) return res.status(401).json({ error: "Accès refusé. Token manquant." });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token invalide." });
    req.user = user; // { userId: id }
    next();
  });
};

// -- Auth Routes --
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Check if user exists
    const existingUser = await prisma.user.findUnique({ where: { username } });
    if (existingUser) {
      return res.status(400).json({ error: "Cet utilisateur existe déjà." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword
      }
    });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, username: user.username });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) {
      return res.status(400).json({ error: "Identifiants incorrects." });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Identifiants incorrects." });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: user.username });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { newUsername, currentPassword, newPassword } = req.body;
    
    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) {
      return res.status(404).json({ error: "Utilisateur introuvable." });
    }

    // Verify current password always required for security
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: "Le mot de passe actuel est incorrect." });
    }

    let updateData = {};

    // Handle username update
    if (newUsername && newUsername !== user.username) {
      const existingUser = await prisma.user.findUnique({ where: { username: newUsername } });
      if (existingUser) {
        return res.status(400).json({ error: "Ce nom d'utilisateur est déjà pris." });
      }
      updateData.username = newUsername;
    }

    // Handle password update
    if (newPassword) {
      updateData.password = await bcrypt.hash(newPassword, 10);
    }

    if (Object.keys(updateData).length > 0) {
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: updateData
      });
      res.json({ message: "Profil mis à jour avec succès", username: updatedUser.username });
    } else {
      res.json({ message: "Aucune modification apportée", username: user.username });
    }

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// -- Protected Product Routes --

// Get all available products
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { 
        userId: req.user.userId,
        status: 'AVAILABLE' 
      }
    });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get sold products
app.get('/api/products/sold', authenticateToken, async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { 
        userId: req.user.userId,
        status: 'SOLD' 
      }
    });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a new product
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, quantity, purchasePrice } = req.body;
    const product = await prisma.product.create({
      data: {
        name,
        quantity: Number(quantity),
        purchasePrice: Number(purchasePrice),
        sellingPrice: 0, // Default to 0, updated when sold
        userId: req.user.userId
      }
    });
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark as sold
app.put('/api/products/:id/sell', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { sellingPrice } = req.body;
    
    // Check if the product belongs to the user
    const productExists = await prisma.product.findFirst({
      where: { id: Number(id), userId: req.user.userId }
    });
    
    if (!productExists) {
      return res.status(404).json({ error: "Produit non trouvé ou non autorisé." });
    }

    const product = await prisma.product.update({
      where: { id: Number(id) },
      data: { 
        status: 'SOLD',
        sellingPrice: Number(sellingPrice)
      }
    });
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get statistics
app.get('/api/stats', authenticateToken, async (req, res) => {
  try {
    const availableProducts = await prisma.product.findMany({
      where: { userId: req.user.userId, status: 'AVAILABLE' }
    });
    
    const soldProducts = await prisma.product.findMany({
      where: { userId: req.user.userId, status: 'SOLD' }
    });

    let totalCapital = 0;
    let expectedRevenue = 0;
    
    availableProducts.forEach(p => {
      totalCapital += (p.purchasePrice * p.quantity);
      expectedRevenue += (p.sellingPrice * p.quantity);
    });

    let totalProfit = 0;
    soldProducts.forEach(p => {
      totalProfit += ((p.sellingPrice - p.purchasePrice) * p.quantity);
    });

    res.json({
      totalCapital,
      expectedRevenue,
      expectedProfit: expectedRevenue - totalCapital,
      totalProfit
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
