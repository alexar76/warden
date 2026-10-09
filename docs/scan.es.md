# Analiza los servidores que inician tus clientes MCP

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · **Español** · [Français](scan.fr.md) · [中文](scan.zh.md)

`warden-mcp scan` lee la configuración MCP que ya tienes, se conecta a cada servidor que inicia y revisa las definiciones de herramientas antes de que un modelo las vea. Es la misma cadena de compuertas que [`wrap`](../README-es.md) y la [biblioteca](integration.es.md), ejecutada una vez sobre tus configuraciones en lugar de delante de un solo servidor.

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 9 sha256-nC+ybcePE8AW… · block at high
  read .mcp.json (claude-code, 3 servers)

  ✓ allow   notes        claude-code    1 tool · score 0.90
  ✗ BLOCK   evil-notes   claude-code    1 tool · score 0.00 · TOOL_DEF_EXFIL(notes) TOOL_DEF_SECRET_REQUEST(notes)
  ! error   broken       claude-code    could not start: spawn /nonexistent/bin/server ENOENT

3 servers: 1 allowed, 1 blocked, 1 not checked, 0 skipped.
```

Sin cuenta, sin clave de API, sin modelo. El único tráfico de red va a los servidores de tu configuración y, si pasas `--histor`, al registro HISTOR.

## Dónde busca

Sin argumentos, cada archivo de la tabla que exista. Pasa archivos para analizar solo esos, `--project` para los archivos del proyecto en el directorio de trabajo, o `--client NAME` para un solo cliente.

| Cliente | Archivo del proyecto | Archivo del usuario |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (servidores del usuario y de este proyecto) |
| Claude Desktop | — | `claude_desktop_config.json` en el directorio de configuración de la aplicación |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` (JSONC) | `mcp.json` en el directorio de ajustes del usuario |
| Windsurf | — | `~/.codeium/windsurf/mcp_config.json` |

Un servidor que la configuración inicia mediante `warden-mcp wrap` se analiza como el servidor que hay detrás del envoltorio, con el id de pin que usa `wrap`, de modo que la deriva respecto de la instantánea aprobada aparece en el informe. Las entradas desactivadas, las que necesitan un valor `${input:…}` que el cliente pide al usuario y las que no tienen ni `command` ni `url` se listan como omitidas; nunca desaparecen en silencio.

## Iniciar servidores

Para leer las herramientas de un servidor stdio, `scan` lo inicia con el comando, los argumentos y el entorno de la configuración, igual que lo haría tu cliente, y lo detiene después de `tools/list`. Nunca llama a una herramienta. Aun así, el programa se ejecuta. Donde no lo quieras, por ejemplo en CI sobre un pull request, `--no-launch` revisa solo la línea de arranque: los registros de comandos del threat feed y la identidad de arranque del lock.

Los servidores remotos (`url`, streamable HTTP o el antiguo HTTP+SSE) se consultan por la red con las cabeceras de la configuración. `--public-only` rechaza los que se resuelven a direcciones loopback, privadas, link-local o de metadatos de la nube, comprobando la dirección a la que realmente se conecta. No se siguen redirecciones.

## Salida y códigos de salida

| Opción | Escribe |
|---|---|
| (por defecto) | una tabla en stdout |
| `--json` | el informe JSON en stdout |
| `--json-file FILE` | el informe JSON en un archivo, junto con la tabla |
| `--sarif FILE` | SARIF 2.1.0 para GitHub code scanning; solo hallazgos que bloquean, ubicados en la línea del servidor en la configuración |
| `--markdown FILE` | un resumen con detalles plegables, para `$GITHUB_STEP_SUMMARY` o un comentario en el PR |

Código `0`: nada bloqueado. `1`: se bloqueó un servidor o, con `--fail-on-error`, no se pudo comprobar. `2`: error de uso o de configuración. `--fail-on SEVERITY` mueve el umbral de bloqueo; `--policy FILE` acepta el mismo archivo de política estricto que `wrap`.

Las credenciales en líneas de arranque y URL se muestran como `***`. Las descripciones de herramientas del informe Markdown van dentro de bloques de código que ese texto no puede cerrar.

## El archivo lock: revisa las definiciones, no solo el comando

Una línea de configuración dice qué programa arranca. No dice qué le contará ese programa a tu modelo. El lock registra lo segundo, para que un pull request lo muestre.

```bash
warden-mcp scan --project --lock warden.lock.json --update-lock   # después de leer qué cambió
git add .mcp.json warden.lock.json
```

`--update-lock` escribe la identidad de arranque de cada servidor y sus definiciones completas, y se niega a registrar un servidor que WARDEN bloquea. Volver a ejecutarlo sobre servidores sin cambios no modifica el archivo. Solo con `--lock`:

- un servidor que el lock no conoce se bloquea (`LOCK_MISSING`);
- un servidor que arranca de otra forma se bloquea (`SERVER_IDENTITY_DRIFT`);
- un servidor que ahora anuncia otras herramientas se bloquea (`TOOL_DEF_DRIFT`), y el informe Markdown muestra el cambio como un diff de nombres, descripciones y esquemas.

Las entradas del lock que ninguna configuración inicia se listan y se eliminan en la siguiente actualización.

## GitHub Action

```yaml
name: MCP servers
on: [pull_request]
permissions:
  contents: read
  security-events: write   # solo para upload-sarif
jobs:
  warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alexar76/warden@v0.9.0
        with:
          upload-sarif: 'true'
```

Por defecto lee los archivos del proyecto, no inicia servidores stdio (ese programa lo elige el pull request), rechaza direcciones no públicas, usa `warden.lock.json` si existe, escribe el resumen del job y falla ante un servidor bloqueado. Entradas: `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `sarif`, `upload-sarif`, `version`. Salidas: `blocked`, `servers`, `sarif`. En workflows de producción, fija la acción por SHA de commit.

## pre-commit

```yaml
repos:
  - repo: https://github.com/alexar76/warden
    rev: v0.9.0
    hooks:
      - id: warden-scan     # configuraciones modificadas; no inicia servidores stdio
      - id: warden-lock     # el proyecto coincide con warden.lock.json; inicia servidores stdio
```

Ambos ejecutan el paquete publicado mediante `npx`, así que necesitas Node 20 o posterior en el `PATH`.

## Plugin de Claude Code

```text
/plugin marketplace add alexar76/warden
/plugin install warden@warden
```

Al iniciar la sesión analiza los servidores que Claude Code inicia para el proyecto, te dice cuáles están bloqueados y al modelo solo le da el nombre y el código del hallazgo. Una descripción bloqueada nunca entra en el contexto del modelo. Después, un hook `PreToolUse` deniega las llamadas a herramientas de un servidor bloqueado o a una herramienta bloqueada; lee un archivo pequeño y no inicia nada. Detalles y límites: [claude-plugin/README.md](../claude-plugin/README.md).

## HISTOR: ¿este servidor te sirve lo mismo que a todos?

[HISTOR](https://histor.modelmarket.dev) es un registro público que anota cada día las definiciones de herramientas de todos los servidores remotos del registro oficial de MCP. `--histor` le hace una pregunta por cada servidor remoto: ¿el conjunto de herramientas que te acaban de servir es el que observa HISTOR?

Qué se envía: el endpoint, solo esquema, host y ruta (sin query, sin usuario ni contraseña), y el digest [MTL/1](https://github.com/alexar76/awr) del conjunto de herramientas. Ninguna descripción de herramienta, ninguna cabecera, ningún servidor stdio. Los endpoints en hosts o direcciones privadas, y las rutas que parecen llevar una clave, no se envían; el informe dice por qué.

| Respuesta | Significado |
|---|---|
| `same` | Te sirvieron el conjunto que HISTOR observa ahora |
| `different` | HISTOR nunca vio este conjunto: cambió después del último rastreo diario, o el servidor te sirve algo que no sirve al rastreador público. Se informa como hallazgo consultivo `HISTOR_UNSEEN_TOOLSET` |
| `previously-observed` | Un conjunto que HISTOR vio antes, no el actual. Hallazgo consultivo `HISTOR_OLDER_TOOLSET` |
| `not-listed`, `not-observed` | HISTOR no conoce este endpoint o todavía no lo ha leído con éxito |

Las respuestas de HISTOR nunca bloquean. Si HISTOR no responde, se informa y el análisis continúa.

## Lo que scan no hace

- Lee las definiciones una vez. Un servidor que cambie después lo detecta el siguiente análisis, el lock en CI o `wrap` en cada llamada.
- No analiza argumentos ni resultados de llamadas, prompts ni resources, y no es un sandbox: iniciar un servidor stdio lo ejecuta.
- Sus veredictos son las reglas estáticas y los registros de amenazas de WARDEN. Una paráfrasis que ninguna regla cubre pasa; consulta [la cadena de compuertas](gates.es.md) y el [estudio de campo](mcp-survey.es.md) para ver qué detectan las reglas y con qué frecuencia se equivocan.
