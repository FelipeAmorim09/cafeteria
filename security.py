"""Utilidades de segurança: CSRF, rate limiting, validações e headers HTTP."""
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, flash, g, redirect, request, session, url_for

# ---------------------------------------------------------------------------
# Rate limiting (em memória, por IP). Suficiente para uso local / instância
# única; em produção trocar por Redis ou um WAF na frente da aplicação.
# ---------------------------------------------------------------------------
_tentativas = defaultdict(deque)
_trava = threading.Lock()


def rate_limit_ok(chave, max_tentativas=10, janela_segundos=60):
    agora = time.monotonic()
    with _trava:
        fila = _tentativas[chave]
        while fila and agora - fila[0] > janela_segundos:
            fila.popleft()
        if len(fila) >= max_tentativas:
            return False
        fila.append(agora)
        return True


# ---------------------------------------------------------------------------
# CSRF — token por sessão, comparação em tempo constante.
# ---------------------------------------------------------------------------
def csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']


def validar_csrf():
    enviado = request.form.get('csrf_token', '')
    esperado = session.get('_csrf_token', '')
    if not esperado or not secrets.compare_digest(enviado, esperado):
        abort(400, description='Token CSRF inválido ou ausente.')


# ---------------------------------------------------------------------------
# Validações de entrada
# ---------------------------------------------------------------------------
UFS_VALIDAS = {
    'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS',
    'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC',
    'SP', 'SE', 'TO',
}

RE_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def email_valido(email):
    return bool(email) and len(email) <= 254 and RE_EMAIL.match(email)


def usuario_valido(nome):
    return bool(nome) and 3 <= len(nome.strip()) <= 50


def senha_forte(senha):
    """Política de senha: mínimo 8 caracteres, com letras e números."""
    if not senha or len(senha) < 8 or len(senha) > 128:
        return False
    return bool(re.search(r'[A-Za-z]', senha)) and bool(re.search(r'\d', senha))


# ---------------------------------------------------------------------------
# Validação de upload de imagem (extensão + assinatura mágica do arquivo)
# ---------------------------------------------------------------------------
EXTENSOES_PERMITIDAS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

_ASSINATURAS = (
    (b'\x89PNG\r\n\x1a\n', '.png'),
    (b'\xff\xd8\xff', '.jpg'),
    (b'GIF87a', '.gif'),
    (b'GIF89a', '.gif'),
)


def imagem_valida(arquivo):
    """Confere extensão e os bytes iniciais (magic bytes) do arquivo.

    Retorna a extensão normalizada se válido, ou None.
    """
    nome = (arquivo.filename or '').lower()
    ext = '.' + nome.rsplit('.', 1)[-1] if '.' in nome else ''
    if ext == '.jpeg':
        ext = '.jpg'
    if ext not in EXTENSOES_PERMITIDAS:
        return None

    cabecalho = arquivo.stream.read(16)
    arquivo.stream.seek(0)

    if cabecalho[:4] == b'RIFF' and cabecalho[8:12] == b'WEBP':
        return '.webp' if ext == '.webp' else None
    for assinatura, ext_esperada in _ASSINATURAS:
        if cabecalho.startswith(assinatura):
            return ext if ext == ext_esperada or (ext == '.jpg' and ext_esperada == '.jpg') else None
    return None


# ---------------------------------------------------------------------------
# Decorators de autorização (RBAC simples: usuário comum x administrador)
# ---------------------------------------------------------------------------
def login_obrigatorio(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get('user') is None:
            flash('Faça login para acessar essa página.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapper


def admin_obrigatorio(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get('user') is None:
            flash('Faça login para acessar essa página.', 'warning')
            return redirect(url_for('login'))
        if not g.user['is_admin']:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Headers de segurança HTTP
# ---------------------------------------------------------------------------
CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "img-src 'self' data:; "
    "media-src 'self'; "
    "font-src 'self' data: https://cdn.jsdelivr.net https://fonts.gstatic.com; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


def aplicar_headers_seguranca(resposta):
    resposta.headers.setdefault('Content-Security-Policy', CSP)
    resposta.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resposta.headers.setdefault('X-Frame-Options', 'DENY')
    resposta.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    resposta.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    if request.is_secure:
        resposta.headers.setdefault(
            'Strict-Transport-Security', 'max-age=31536000; includeSubDomains'
        )
    return resposta
