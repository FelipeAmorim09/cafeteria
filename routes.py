"""Rotas da aplicação: páginas públicas, autenticação, perfil e administração."""
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    current_app, flash, g, redirect, render_template, request, session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db, registrar_auditoria
from security import (
    admin_obrigatorio, email_valido, imagem_valida, login_obrigatorio,
    rate_limit_ok, senha_forte, usuario_valido, validar_csrf, UFS_VALIDAS,
)

MAX_FALHAS_LOGIN = 5
MINUTOS_BLOQUEIO = 15
AVATAR_PADRAO = 'imagens/default_avatar.png'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _foto_url(row):
    if row['profile_image']:
        return url_for('static', filename='uploads/' + row['profile_image'])
    return url_for('static', filename=AVATAR_PADRAO)


def _user_dict(row):
    return {
        'id': row['id'],
        'username': row['usuario'],
        'profileImageUrl': _foto_url(row),
        'descricao': row['descricao'],
        'data_nascimento': row['data_nascimento'],
        'genero': row['genero'],
        'biografia': row['biografia'],
        'is_admin': bool(row['is_admin']),
    }


def _salvar_foto(arquivo):
    """Valida e salva a imagem de perfil com nome aleatório. Retorna o nome ou None."""
    ext = imagem_valida(arquivo)
    if not ext:
        return None
    nome = uuid.uuid4().hex + ext
    pasta = Path(current_app.config['UPLOAD_FOLDER'])
    pasta.mkdir(parents=True, exist_ok=True)
    arquivo.save(pasta / nome)
    return nome


def _ip():
    return request.remote_addr


# ---------------------------------------------------------------------------
# Páginas públicas
# ---------------------------------------------------------------------------
def index():
    return render_template('index.html')


def menu():
    return render_template('menu.html')


# ---------------------------------------------------------------------------
# Cadastro
# ---------------------------------------------------------------------------
def cadastro():
    if request.method == 'POST':
        if not rate_limit_ok(f'cadastro:{_ip()}', max_tentativas=10, janela_segundos=60):
            flash('Muitas tentativas. Aguarde um minuto e tente novamente.', 'danger')
            return redirect(url_for('cadastro'))
        validar_csrf()

        usuario = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        uf = (request.form.get('uf') or '').strip().upper()
        senha = request.form.get('password') or ''
        confirmacao = request.form.get('confirmPassword') or ''

        erros = []
        if not usuario_valido(usuario):
            erros.append('Nome de usuário deve ter entre 3 e 50 caracteres.')
        if not email_valido(email):
            erros.append('E-mail inválido.')
        if uf not in UFS_VALIDAS:
            erros.append('Selecione um estado válido.')
        if not senha_forte(senha):
            erros.append('A senha deve ter no mínimo 8 caracteres, com letras e números.')
        if senha != confirmacao:
            erros.append('As senhas não coincidem!')
        if erros:
            for erro in erros:
                flash(erro, 'danger')
            return redirect(url_for('cadastro'))

        db = get_db()
        if db.execute('SELECT 1 FROM usuarios WHERE email = ?', (email,)).fetchone():
            flash('E-mail já registrado!', 'danger')
            return redirect(url_for('cadastro'))

        foto = ''
        arquivo = request.files.get('profile_image')
        if arquivo and arquivo.filename:
            foto = _salvar_foto(arquivo)
            if foto is None:
                flash('Imagem inválida. Use PNG, JPG, GIF ou WEBP.', 'danger')
                return redirect(url_for('cadastro'))

        # O primeiro usuário cadastrado vira administrador.
        primeiro = db.execute('SELECT COUNT(*) AS n FROM usuarios').fetchone()['n'] == 0
        cursor = db.execute(
            'INSERT INTO usuarios (usuario, email, uf, senha_hash, profile_image, is_admin) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (usuario, email, uf, generate_password_hash(senha), foto, int(primeiro)),
        )
        db.commit()
        registrar_auditoria('cadastro', usuario_id=cursor.lastrowid, email=email, ip=_ip())

        # Nova sessão após autenticar (evita session fixation).
        session.clear()
        session.permanent = True
        session['user_id'] = cursor.lastrowid

        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('perfil'))

    return render_template('cadastro.html')


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------
def login():
    if request.method == 'POST':
        if not rate_limit_ok(f'login:{_ip()}', max_tentativas=10, janela_segundos=60):
            flash('Muitas tentativas. Aguarde um minuto e tente novamente.', 'danger')
            return redirect(url_for('login'))
        validar_csrf()

        email = (request.form.get('email') or '').strip().lower()
        senha = request.form.get('password') or ''
        generico = 'E-mail ou senha incorretos.'  # mensagem única: não revela se o e-mail existe

        db = get_db()
        row = db.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()

        if row is None:
            registrar_auditoria('login_falha', email=email, ip=_ip())
            flash(generico, 'danger')
            return redirect(url_for('login'))

        if row['bloqueado_ate']:
            bloqueado_ate = datetime.fromisoformat(row['bloqueado_ate'])
            if datetime.now(timezone.utc) < bloqueado_ate:
                flash('Conta temporariamente bloqueada por excesso de tentativas. '
                      'Tente novamente mais tarde.', 'danger')
                return redirect(url_for('login'))

        if not check_password_hash(row['senha_hash'], senha):
            falhas = row['falhas_login'] + 1
            bloqueio = None
            if falhas >= MAX_FALHAS_LOGIN:
                bloqueio = (datetime.now(timezone.utc) + timedelta(minutes=MINUTOS_BLOQUEIO)).isoformat()
                falhas = 0
            db.execute(
                'UPDATE usuarios SET falhas_login = ?, bloqueado_ate = ? WHERE id = ?',
                (falhas, bloqueio, row['id']),
            )
            db.commit()
            registrar_auditoria('login_falha', usuario_id=row['id'], email=email, ip=_ip())
            flash(generico, 'danger')
            return redirect(url_for('login'))

        db.execute(
            'UPDATE usuarios SET falhas_login = 0, bloqueado_ate = NULL WHERE id = ?',
            (row['id'],),
        )
        db.commit()
        registrar_auditoria('login_sucesso', usuario_id=row['id'], email=email, ip=_ip())

        session.clear()
        session.permanent = True
        session['user_id'] = row['id']
        return redirect(url_for('index'))

    return render_template('login.html')


def logout():
    if g.user:
        registrar_auditoria('logout', usuario_id=g.user['id'], email=g.user['email'], ip=_ip())
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Perfil
# ---------------------------------------------------------------------------
@login_obrigatorio
def perfil():
    return render_template('perfil.html', user=_user_dict(g.user))


@login_obrigatorio
def gerenciap():
    return render_template('gerenciap.html', usuario=_user_dict(g.user))


@login_obrigatorio
def editar_perfil():
    if request.method == 'POST':
        validar_csrf()

        novo_nome = (request.form.get('user') or '').strip()
        descricao = (request.form.get('descricao') or '').strip()[:500]
        data_nascimento = (request.form.get('data_nascimento') or '').strip()
        genero = (request.form.get('genero') or '').strip()[:30]
        biografia = (request.form.get('biografia') or '').strip()[:1000]

        if novo_nome and not usuario_valido(novo_nome):
            flash('Nome de usuário deve ter entre 3 e 50 caracteres.', 'danger')
            return redirect(url_for('editar_perfil'))

        foto = g.user['profile_image']
        arquivo = request.files.get('profile_image')
        if arquivo and arquivo.filename:
            nova_foto = _salvar_foto(arquivo)
            if nova_foto is None:
                flash('Imagem inválida. Use PNG, JPG, GIF ou WEBP.', 'danger')
                return redirect(url_for('editar_perfil'))
            foto = nova_foto

        db = get_db()
        db.execute(
            'UPDATE usuarios SET usuario = ?, profile_image = ?, descricao = ?, '
            'data_nascimento = ?, genero = ?, biografia = ? WHERE id = ?',
            (novo_nome or g.user['usuario'], foto, descricao,
             data_nascimento, genero, biografia, g.user['id']),
        )
        db.commit()
        registrar_auditoria('perfil_editado', usuario_id=g.user['id'],
                            email=g.user['email'], ip=_ip())
        flash('Perfil atualizado com sucesso!', 'success')
        return redirect(url_for('gerenciap'))

    return render_template('editar_perfil.html', usuario=_user_dict(g.user))


# ---------------------------------------------------------------------------
# Administração (somente admins)
# ---------------------------------------------------------------------------
@admin_obrigatorio
def admin_page():
    db = get_db()
    usuarios = db.execute(
        'SELECT id, usuario, email, uf, is_admin, criado_em FROM usuarios '
        'ORDER BY criado_em DESC'
    ).fetchall()
    eventos = db.execute(
        'SELECT acao, email, ip, criado_em FROM auditoria '
        'ORDER BY id DESC LIMIT 50'
    ).fetchall()
    return render_template('administrador.html', usuarios=usuarios, eventos=eventos)


# ---------------------------------------------------------------------------
# Registro das rotas (endpoints sem prefixo, como os templates esperam)
# ---------------------------------------------------------------------------
def register(app):
    @app.context_processor
    def _injetar_usuario_navbar():
        """Disponibiliza `current_user` para a navbar em todos os templates."""
        return {'current_user': _user_dict(g.user) if g.get('user') else None}

    app.add_url_rule('/', view_func=index)
    app.add_url_rule('/menu', view_func=menu)
    app.add_url_rule('/cadastro', view_func=cadastro, methods=['GET', 'POST'])
    app.add_url_rule('/login', view_func=login, methods=['GET', 'POST'])
    app.add_url_rule('/logout', view_func=logout)
    app.add_url_rule('/perfil', view_func=perfil)
    app.add_url_rule('/gerenciap', view_func=gerenciap)
    app.add_url_rule('/editar_perfil', view_func=editar_perfil, methods=['GET', 'POST'])
    app.add_url_rule('/admin', view_func=admin_page)
