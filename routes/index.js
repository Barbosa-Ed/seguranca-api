const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.send('Bem-vindo à API');
});

module.exports = router;