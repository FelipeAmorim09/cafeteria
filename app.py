"""Cafeteria — aplicação Flask.

Configurações sensíveis (SECRET_KEY etc.) vêm de variáveis de ambiente /
arquivo .env, que fica fora do controle de versão (ver .gitignore).
"""
import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, render_template, request, session

import database
import routes
import security

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / '.env'


def _obter_secret_key():
    """Lê a SECRET_KEY do .env; se não existir, gera uma aleatória e persiste."""
    load_dotenv(ENV_PATH)
    chave = os.environ.get('SECRET_KEY')
    if not chave:
        chave = secrets.token_hex(32)
        with open(ENV_PATH, 'a', encoding='utf-8') as f:
            f.write(f'SECRET_KEY={chave}\n')
    return chave


def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=_obter_secret_key(),
        DATABASE=str(BASE_DIR / 'instance' / 'cafeteria.db'),
        UPLOAD_FOLDER=str(BASE_DIR / 'static' / 'uploads'),
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # uploads limitados a 5 MB
        # Cookies de sessão endurecidos
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', '0') == '1',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    )

    database.init_app(app)
    routes.register(app)

    @app.before_request
    def carregar_usuario():
        g.user = None
        user_id = session.get('user_id')
        if user_id is not None:
            g.user = database.get_db().execute(
                'SELECT * FROM usuarios WHERE id = ?', (user_id,)
            ).fetchone()
            if g.user is None:
                session.clear()

    @app.after_request
    def headers_seguranca(resposta):
        return security.aplicar_headers_seguranca(resposta)

    @app.context_processor
    def injetar_csrf():
        return {'csrf_token': security.csrf_token}

    # Handlers de erro genéricos — nunca vazam stack trace ou detalhes internos.
    def _pagina_erro(codigo, titulo, mensagem):
        return render_template('erro.html', codigo=codigo, titulo=titulo,
                               mensagem=mensagem), codigo

    @app.errorhandler(400)
    def requisicao_invalida(_e):
        return _pagina_erro(400, 'Requisição inválida',
                            'Algo deu errado com o envio. Volte e tente novamente.')

    @app.errorhandler(403)
    def acesso_negado(_e):
        return _pagina_erro(403, 'Acesso negado',
                            'Você não tem permissão para acessar essa página.')

    @app.errorhandler(404)
    def nao_encontrado(_e):
        return _pagina_erro(404, 'Página não encontrada',
                            'A página que você procura não existe ou foi movida.')

    @app.errorhandler(413)
    def arquivo_grande(_e):
        return _pagina_erro(413, 'Arquivo muito grande',
                            'O limite para envio de imagens é 5 MB.')

    @app.errorhandler(500)
    def erro_interno(_e):
        app.logger.exception('Erro interno')
        return _pagina_erro(500, 'Ocorreu um erro interno',
                            'Nossa equipe já foi avisada. Tente novamente em instantes.')

    return app


app = create_app()

if __name__ == '__main__':
    # debug desligado por padrão; ative apenas em desenvolvimento via .env
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='127.0.0.1', port=5000, debug=debug)
