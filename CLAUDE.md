# CLAUDE.md — osint-recon

Instrucciones permanentes para Claude Code al trabajar en este repositorio.

## Qué es este repo
`osint-recon`: herramienta de línea de comandos en Python que agrega información
**pública** sobre un dominio u organización (subdominios, correos, tecnologías,
metadatos de documentos y brechas conocidas) de forma asíncrona y la consolida en
informes Markdown y JSON. También revisa la huella digital propia del usuario.

Se desarrolla en Windows y se usa también en Kali/Parrot. No depende de
herramientas de Linux: todo es HTTP y DNS desde Python.

## Ámbito ético (innegociable)
- Solo para dominios u organizaciones con **autorización**, o para la huella
  digital **propia**. **No** es una herramienta para buscar o perfilar personas.
- Las salvaguardas están en el código y tienen tests. **No las debilites ni las
  quites**, y añade un test por cada salvaguarda nueva:
  - las fuentes activas (web, documentos, DNS) solo se ejecutan con el dominio en
    `scope` o con `--authorized`;
  - los correos encontrados **nunca** se consultan uno a uno en HIBP; solo
    `/breacheddomain` (dominio verificado) y `owned_emails` vía `footprint`;
  - nada de redes sociales ni de cruzar datos de una persona entre fuentes;
  - `--redact-people` enmascara correos y nombres;
  - se respetan `robots.txt`, los límites de rastreo y los rate limits.
- No añadas fuentes que violen los términos de uso: nada de scraping de Google,
  Bing o LinkedIn.
- Nada de datos reales en el repo: ejemplos y fixtures usan `example.com`, IPs de
  documentación (192.0.2.x, 198.51.100.x, 203.0.113.x) y personas ficticias.
  `reports/` y `*.log` están en `.gitignore`.
- Claves de API solo en variables de entorno (`OSINT_RECON_*_KEY`), nunca en el
  repo. `SecretFilter` las enmascara en los logs: no lo quites.

## Git (innegociable)
- **Nunca** hagas commit, crees el repo en GitHub, hagas push ni cambies la
  visibilidad sin mi OK expreso. No publiques en PyPI.
- Commits **sin** `Co-Authored-By` ni ninguna mención a Claude o a una IA.
  El autor local de este repo es `SpromBash`.
- Mensajes en imperativo (`Add Shodan source`, `Fix robots.txt handling`).
- Antes de cada commit, enséñame `git status` y `git diff`.

## Forma de trabajar
- Primero un plan; cambios pequeños, verificables y reversibles.
- Explícame qué haces y por qué, y qué comandos usas: quiero aprender.
- No afirmes que algo funciona sin comprobarlo. Si algo no se puede comprobar
  aquí (por ejemplo, contra las APIs reales), dilo claramente.

## Comandos (Windows, desde la raíz)
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\pytest.exe -q
.\.venv\Scripts\pytest.exe --cov=osint_recon --cov-branch --cov-report=term-missing
.\.venv\Scripts\mypy.exe
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\python.exe -m build ; .\.venv\Scripts\twine.exe check dist/*
```
Un cambio no está terminado hasta que pasan pytest, mypy y ruff.

## Convenciones técnicas
- `mypy --strict` en todo, sin `# type: ignore` injustificados.
- **Los tests nunca usan la red.** HTTP con `respx` (una petición sin mock hace
  fallar el test); DNS, reloj y `sleep` inyectados; documentos generados en
  memoria (`tests/docfactory.py`).
- Una fuente nueva = una clase que hereda de `sources.base.Source`
  (`name`, `active`, `stage`, `key_name`, `async collect(ctx)`), registrada en
  `runner.domain_sources()`, con su sección en `default_config.yaml`
  (`SOURCE_NAMES` en `config.py`) y sus tests con fixtures realistas.
- Las fuentes lanzan `SourceError` para fallos previstos; nunca deben tumbar la
  ejecución entera. Los errores de usuario son `OsintError` con `exit_code`.
- Todo lo que venga de fuera (HTML, documentos, JSON de APIs) es no fiable:
  valida tipos y formatos y no confíes en extensiones ni en `Content-Length`.
- Dependencias en tiempo de ejecución: typer, pyyaml, httpx, dnspython, pypdf.
  Pregúntame antes de añadir otra.
