### Registro
curl -X POST http://localhost:3000/auth/register \
-H "Content-Type: application/json" \
-d "{\"username\":\"teste\",\"email\":\"teste@exemplo.com\",\"password\":\"SENHA\"}"

### Login
curl -X POST http://localhost:3000/auth/login \
-H "Content-Type: application/json" \
-d "{\"email\":\"teste@exemplo.com\",\"password\":\"SENHA\"}"

OU (modo verboso)
curl -v -X POST http://localhost:3000/auth/login \
-H "Content-Type: application/json" \
-d "{\"email\":\"teste@exemplo.com\",\"password\":\"SENHA\"}"

### Verificação
curl -X POST http://localhost:3000/auth/verify \
-H "Content-Type: application/json" \
-d "{\"email\":\"teste@exemplo.com\",\"code\":\"CÓDIGO\"}"

### Rota protegida
curl -X GET http://localhost:3000/auth/protected \
-H "Authorization: Bearer TOKEN_DE_ACESSO" (Token enviado no momento do login)

### Atualização de token
curl -X POST http://localhost:3000/auth/refresh-token \
-b "refreshToken=REFRESH_TOKEN" (Utilizar modo verboso do CURL no login)

### "Esqueci a senha"
curl -X POST http://localhost:3000/auth/forgot-password \
-H "Content-Type: application/json" \
-d "{\"email\":\"teste@exemplo.com\"}"

### Redefinir senha
curl -X POST http://localhost:3000/auth/reset-password \
-H "Content-Type: application/json" \
-d "{\"token\":\"TOKEN_DE_ACESSO\",\"newPassword\":\"SENHA_NOVA\"}"