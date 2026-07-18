"""Gera a versão vitrine estática do site em docs/ para o GitHub Pages.

O Pages não executa Python, então este script renderiza as páginas públicas
(home e menu) como HTML puro e ajusta os links:
  - /menu  -> menu.html   |   /  -> index.html
  - Login/Cadastro -> botão "Código no GitHub" (não há servidor na vitrine)
  - seção do vídeo é removida (o .mp4 de 52 MB não vai para o docs/)

Uso:  py build_static.py
"""
import re
import shutil
from pathlib import Path

from app import app

REPO_URL = 'https://github.com/FelipeAmorim09/cafeteria'
BASE = Path(__file__).resolve().parent
DOCS = BASE / 'docs'

BOTAO_GITHUB = (
    '<div class="d-flex flex-column flex-lg-row gap-2 auth-actions">'
    f'<a class="btn btn-cafe" href="{REPO_URL}" target="_blank" rel="noopener">'
    '<i class="bi bi-github me-1"></i>Código no GitHub</a></div>'
)


def converter(html):
    # Substitui o bloco Login/Cadastro pelo botão do repositório
    html = re.sub(
        r'<div class="d-flex flex-column flex-lg-row gap-2 auth-actions">.*?</div>',
        BOTAO_GITHUB, html, flags=re.DOTALL)
    # Remove a seção do vídeo (o mp4 não é copiado para a vitrine)
    html = re.sub(
        r'<section class="section container-xl pb-4">.*?</section>',
        '', html, flags=re.DOTALL)
    # Reescreve as rotas do Flask para arquivos estáticos
    html = html.replace('href="/#sobre"', 'href="index.html#sobre"')
    html = html.replace('href="/menu"', 'href="menu.html"')
    html = html.replace('href="/cadastro"', f'href="{REPO_URL}"')
    html = html.replace('href="/login"', f'href="{REPO_URL}"')
    html = html.replace('href="/"', 'href="index.html"')
    html = html.replace('/static/', 'static/')
    return html


def main():
    if DOCS.exists():
        shutil.rmtree(DOCS)
    DOCS.mkdir()

    cliente = app.test_client()
    paginas = {'index.html': '/', 'menu.html': '/menu'}
    for arquivo, rota in paginas.items():
        resposta = cliente.get(rota)
        assert resposta.status_code == 200, f'{rota} retornou {resposta.status_code}'
        (DOCS / arquivo).write_text(converter(resposta.get_data(as_text=True)),
                                    encoding='utf-8')
        print(f'  {rota:6} -> docs/{arquivo}')

    # Copia CSS e imagens (sem o vídeo e sem uploads de usuários)
    destino = DOCS / 'static'
    destino.mkdir()
    shutil.copy2(BASE / 'static' / 'styles.css', destino / 'styles.css')
    shutil.copytree(BASE / 'static' / 'imagens', destino / 'imagens',
                    ignore=shutil.ignore_patterns('*.mp4'))

    # Evita que o GitHub Pages tente processar o site com Jekyll
    (DOCS / '.nojekyll').touch()

    print(f'\nVitrine gerada em: {DOCS}')
    print('Abra docs/index.html no navegador para conferir antes de subir.')


if __name__ == '__main__':
    main()
