# ☕ Cafeteria — Web App em Flask

Aplicação web de uma cafeteria com página institucional, cadastro/login de
usuários, perfil editável com foto e painel de administração — construída com
foco em **boas práticas de segurança**.

## Funcionalidades

- Página inicial com carrossel, galeria, depoimentos e vídeo
- Página de menu com cardápio por categorias e preços
- Cadastro de usuários com medidor de força de senha (zxcvbn), prévia de foto e confirmação em tempo real
- Login com bloqueio automático após tentativas falhas e botão mostrar/ocultar senha
- Perfil com foto, descrição, data de nascimento, gênero e biografia
- Painel do administrador (lista de usuários + trilha de auditoria)
- Interface 100% responsiva (mobile-first) com páginas de erro amigáveis

## Stack

- **Backend:** Python 3 + Flask
- **Banco:** SQLite (criado automaticamente no primeiro run, sem configuração)
- **Frontend:** Bootstrap 5.3 + Bootstrap Icons + Jinja2 (layout base compartilhado), fontes Playfair Display / Poppins

## Segurança implementada

| Área | Medida |
|---|---|
| Senhas | Hash com `werkzeug.security` (scrypt) — nunca em texto puro |
| Política de senha | Mínimo de 8 caracteres com letras e números (validação servidor + medidor no cliente) |
| SQL Injection | 100% das consultas parametrizadas |
| XSS | Autoescape do Jinja2 + Content-Security-Policy |
| CSRF | Token por sessão em todos os formulários, comparação em tempo constante |
| Força bruta | Rate limiting por IP + bloqueio temporário da conta após 5 falhas |
| Sessões | Cookies `HttpOnly` + `SameSite=Lax`, expiração de 2h, regeneração no login (anti session fixation) |
| Enumeração de contas | Mensagem de erro genérica no login |
| Uploads | Validação de extensão **e** assinatura do arquivo (magic bytes), nome aleatório, limite de 5 MB |
| Headers HTTP | CSP, HSTS (sob HTTPS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| RBAC | Papéis usuário/administrador com decorators de autorização |
| Auditoria | Registro de cadastro, login (sucesso/falha), logout e edição de perfil, com IP e timestamp |
| Erros | Handlers genéricos — nenhum stack trace ou detalhe interno vaza para o cliente |
| Segredos | `SECRET_KEY` via `.env` (fora do git), gerada aleatoriamente se ausente |

## Como rodar

```bash
# 1. Clone e entre na pasta
git clone <url-do-repo>
cd cafeteria

# 2. Crie o ambiente virtual e instale as dependências
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt

# 3. Rode
python app.py
```

> **Variáveis de ambiente (opcionais):** crie um arquivo `.env` na raiz com
> `SECRET_KEY=...`, `FLASK_DEBUG=1` ou `SESSION_COOKIE_SECURE=1` se quiser
> personalizar. Sem ele, a aplicação gera uma `SECRET_KEY` aleatória
> automaticamente no primeiro run. O `.env` é ignorado pelo git.

Acesse **http://127.0.0.1:5000**.

> **Dica:** o primeiro usuário cadastrado vira administrador automaticamente
> e enxerga o painel em `/admin`.

## Estrutura

```
├── app.py           # Fábrica da aplicação, config, headers e handlers de erro
├── routes.py        # Todas as rotas (páginas, auth, perfil, admin)
├── database.py      # Camada SQLite + schema + auditoria
├── security.py      # CSRF, rate limiting, validações, headers, RBAC
├── templates/       # Páginas Jinja2
├── static/          # CSS, imagens e uploads (uploads fora do git)
└── instance/        # Banco SQLite local (fora do git)
```
