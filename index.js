const express = require('express');
const cookieParser = require('cookie-parser');
const sequelize = require('./config/database');
const indexRouter = require('./routes/index');
const authRouter = require('./routes/auth');
require('dotenv').config();

const app = express();

// Testar conexão com o banco
sequelize.authenticate()
  .then(() => console.log('Conectado ao SQLite'))
  .catch(err => console.error('Erro ao conectar ao SQLite:', err));

// Sincronizar modelos com o banco
sequelize.sync()
  .then(() => console.log('Modelos sincronizados com o banco'))
  .catch(err => console.error('Erro ao sincronizar modelos:', err));

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Rotas
app.use('/', indexRouter);
app.use('/auth', authRouter);

// Iniciar servidor
app.listen(3000, () => {
  console.log('Servidor rodando na porta 3000');
});