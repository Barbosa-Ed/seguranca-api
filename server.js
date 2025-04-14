const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const db = require('./db');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

// ROTA DE CADASTRO
app.post('/cadastro',
  body('username').trim().escape(),
  body('senha').trim().escape(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).send('Dados inválidos');
    }

    const { username, senha } = req.body;
    const senhaCriptografada = await bcrypt.hash(senha, 10);

    db.run('INSERT INTO usuarios (username, senha) VALUES (?, ?)', [username, senhaCriptografada], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Erro ao cadastrar usuário');
      }
      res.send('Usuário cadastrado com sucesso!');
    });
  }
);

// ROTA DE LOGIN
app.post('/login',
  body('username').trim().escape(),
  body('senha').trim().escape(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).send('Dados inválidos');
    }

    const { username, senha } = req.body;

    db.get('SELECT * FROM usuarios WHERE username = ?', [username], async (err, row) => {
      if (err) return res.status(500).send('Erro no servidor');
      if (!row) return res.status(401).send('Usuário não encontrado');

      const senhaValida = await bcrypt.compare(senha, row.senha);
      if (senhaValida) {
        res.send(`Bem-vindo, ${row.username}!`);
      } else {
        res.status(401).send('Senha incorreta');
      }
    });
  }
);

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
