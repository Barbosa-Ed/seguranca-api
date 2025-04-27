const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const fs = require('fs').promises;
const User = require('../models/user');
const authMiddleware = require('../middleware/auth');

// Configurar Nodemailer
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function logToFile(endpoint, data, result) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${endpoint} - Dados: ${JSON.stringify(data)} - ${result}\n`;
  try {
    await fs.appendFile('logs.txt', logMessage);
  } catch (error) {
    console.error('Erro ao escrever log:', error);
  }
}

router.post('/register', [
  body('username')
    .trim()
    .notEmpty().withMessage('Nome de usuário é obrigatório')
    .isLength({ min: 3, max: 20 }).withMessage('Nome de usuário deve ter entre 3 e 20 caracteres')
    .toLowerCase(),
  body('email')
    .isEmail().withMessage('E-mail inválido')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 }).withMessage('Senha deve ter pelo menos 6 caracteres')
    .isString().withMessage('Senha deve ser uma string')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(err => err.msg).join(', ');
      await logToFile('POST /auth/register', { username: req.body.username, email: req.body.email }, `Erro: ${errorMessages}`);
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = generateVerificationCode();
    
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      verificationCode,
      isVerified: false
    });

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verificação de Conta',
      text: `Seu código de verificação é: ${verificationCode}`
    });

    await logToFile('POST /auth/register', { username, email }, 'Sucesso: Usuário registrado');
    res.status(201).send('Usuário registrado. Verifique seu e-mail para ativar a conta.');
  } catch (error) {
    console.log(error);
    await logToFile('POST /auth/register', { username: req.body.username, email: req.body.email }, `Erro: ${error.message}`);
    res.status(500).send('Erro ao registrar usuário: ' + error.message);
  }
});

router.post('/login', [
  body('email')
    .isEmail().withMessage('E-mail inválido')
    .normalizeEmail(),
  body('password')
    .notEmpty().withMessage('Senha é obrigatória')
    .isString().withMessage('Senha deve ser uma string')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(err => err.msg).join(', ');
      await logToFile('POST /auth/login', { email: req.body.email }, `Erro: ${errorMessages}`);
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) {
      await logToFile('POST /auth/login', { email }, 'Erro: Credenciais inválidas');
      return res.status(401).send('Credenciais inválidas');
    }
    if (!user.isVerified) {
      await logToFile('POST /auth/login', { email }, 'Erro: Conta não verificada');
      return res.status(403).send('Conta não verificada. Por favor, verifique seu e-mail.');
    }
    if (!(await bcrypt.compare(password, user.password))) {
      await logToFile('POST /auth/login', { email }, 'Erro: Credenciais inválidas');
      return res.status(401).send('Credenciais inválidas');
    }
    const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user.id }, process.env.REFRESH_SECRET);
    res.cookie('refreshToken', refreshToken, { httpOnly: true });
    
    await logToFile('POST /auth/login', { email }, 'Sucesso: Login realizado');
    res.json({ accessToken });
  } catch (error) {
    console.log(error);
    await logToFile('POST /auth/login', { email: req.body.email }, `Erro: ${error.message}`);
    res.status(500).send('Erro ao fazer login: ' + error.message);
  }
});

router.post('/verify', async (req, res) => {
  try {
    const { email, code } = req.body;
    const user = await User.findOne({ where: { email, verificationCode: code } });
    if (!user) {
      return res.status(400).send('Código de verificação inválido ou e-mail não encontrado.');
    }
    await user.update({ isVerified: true, verificationCode: null });
    res.send('Conta verificada com sucesso.');
  } catch (error) {
    console.log(error);
    res.status(500).send('Erro ao verificar conta: ' + error.message);
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(404).send('Usuário não encontrado');
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await user.update({
      resetPasswordToken: token,
      resetPasswordExpires: Date.now() + 3600000
    });
    
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Redefinição de Senha',
      text: `Clique neste link para redefinir sua senha: ${resetLink}`
    });
    
    res.send('E-mail de redefinição de senha enviado');
  } catch (error) {
    console.log(error);
    res.status(500).send('Erro ao enviar e-mail: ' + error.message);
  }
});

router.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const user = await User.findOne({
      where: {
        resetPasswordToken: token,
        resetPasswordExpires: { [Sequelize.Op.gt]: Date.now() }
      }
    });
    if (!user) return res.status(400).send('Token inválido ou expirado');
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await user.update({
      password: hashedPassword,
      resetPasswordToken: null,
      resetPasswordExpires: null
    });
    
    res.send('Senha redefinida com sucesso');
  } catch (error) {
    console.log(error);
    res.status(500).send('Erro ao redefinir senha: ' + error.message);
  }
});

router.post('/refresh-token', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).send('Nenhum token de atualização');
  
  try {
    const verified = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
    const accessToken = jwt.sign({ userId: verified.userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
  } catch (error) {
    res.status(401).send('Token de atualização inválido');
  }
});

router.get('/protected', authMiddleware, (req, res) => {
  res.send('Esta é uma rota protegida');
});

module.exports = router;