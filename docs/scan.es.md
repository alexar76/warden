# Analiza los servidores que inician tus clientes MCP

> 🌐 [English](scan.md) · [Русский](scan.ru.md) · **Español** · [Français](scan.fr.md) · [中文](scan.zh.md)

`warden-mcp scan` lee la configuración MCP que ya tienes, se conecta a cada servidor que inicia y revisa las definiciones de herramientas antes de que un modelo las vea. Es la misma cadena de compuertas que [`wrap`](../README-es.md) y la [biblioteca](integration.es.md), ejecutada una vez sobre tus configuraciones en lugar de delante de un solo servidor.

```bash
npx -y @aimarket/warden@0.9.0 scan
```

```text
WARDEN scan 0.9.0 · ruleset 10 sha256-lJuKKKV5mtru… · block at high
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

Por defecto lee los archivos del proyecto, no inicia servidores stdio (ese programa lo elige el pull request), rechaza direcciones no públicas, usa `warden.lock.json` si existe, escribe el resumen del job y falla ante un servidor bloqueado. Entradas: `config`, `working-directory`, `lock`, `launch-stdio`, `public-only`, `fail-on`, `histor`, `classifier-url`, `classifier-model`, `classifier-blocks`, `sarif`, `upload-sarif`, `version`. Salidas: `blocked`, `servers`, `sarif`. En workflows de producción, fija la acción por SHA de commit.

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

## El clasificador opcional

Las reglas de WARDEN funcionan sin conexión y de forma determinista, y no ven lo que ninguna regla nombra: una paráfrasis, una instrucción en otro idioma. `--classifier-url` y `--classifier-model` añaden una segunda opinión de un modelo que tú eliges, mediante cualquier endpoint compatible con OpenAI: Ollama, vLLM o LM Studio en local, o una API alojada.

```bash
warden-mcp scan --classifier-url http://localhost:11434/v1 --classifier-model qwen2.5:14b
WARDEN_CLASSIFIER_API_KEY=… warden-mcp scan --classifier-url https://api.deepseek.com --classifier-model deepseek-flash
```

- **Está apagado por defecto y envía el texto de las herramientas.** Con ambos flags, el nombre, la descripción y los esquemas de cada herramienta van a ese endpoint. Un modelo local los mantiene en tu máquina. La clave, si hace falta, viene solo de `WARDEN_CLASSIFIER_API_KEY`, nunca de un flag.
- **Consultivo salvo con `--classifier-blocks`.** Sus veredictos se informan como `TOOL_DEF_CLASSIFIER`. Con `--classifier-blocks`, un veredicto en el umbral de bloqueo o por encima (`high` por defecto) bloquea la herramienta como una regla. Un clasificador que no responde se informa y nunca bloquea.
- **La misma pregunta que HISTOR.** El prompt, las cuatro categorías (`instruction_to_model`, `exfiltration`, `secret_request`, `concealment`) y el formato de respuesta son los del clasificador del registro HISTOR. El texto de las herramientas va entre marcadores con un sufijo aleatorio que no puede falsificar, y la respuesta del modelo se comprueba campo por campo. Con `--histor` también se muestra el veredicto que el propio registro guarda sobre el conjunto que te sirvieron (`HISTOR_CLASSIFIER`, consultivo).
- **No lee anotaciones ni campos de extensión.** Las reglas sí.

Medido el 9 de octubre de 2026 con `deepseek-flash`, el modelo que usa HISTOR, sobre MCPTox (el benchmark publicado que se describe en la comparación de abajo) y sobre nuestros conjuntos:

| | Reglas (v10) | Reglas + clasificador, bloqueando en `high` | Reglas + cualquier marca del clasificador (consultiva) |
|---|---|---|---|
| Mitad reservada de MCPTox, detectadas de 218 herramientas envenenadas | 171 | 191 | 218 |
| 45 servidores limpios de MCPTox, bloqueados o marcados | 0 | 0 | 4 marcados |
| 200 servidores del corpus elegidos al azar, bloqueados o marcados | 2 bloqueados | 2 bloqueados | 2 bloqueados, 12 marcados más |
| 23 ataques nuestros / 12 casos benignos difíciles | 20 / 0 | 22 / 0 | 23 / 0 |

Los dos que bloquean las reglas son el servicio de identidad y la herramienta de despliegue de la comparación de abajo. Los 13 servidores que marcó el clasificador lo fueron con `medium` o `low`, nunca `high`. Seis merecen que los mire una persona: uno le dice al modelo que haga una transferencia irreversible de un nombre ENS «como primera y única acción» sin preguntar al usuario, otro que no revele de dónde salen sus datos. El modelo también marca el servidor oficial Fetch, cuya descripción le dice al modelo que ahora tiene acceso a internet y no debe negarse. Es una instrucción al modelo, aunque no un ataque. El modelo no detectó lo que sí detectan las reglas: una inyección en anotaciones, una clave privada o frase semilla pedida como parámetro y `rm -rf ~`.

## Cómo se compara

El 9 de octubre de 2026 ejecutamos WARDEN, mcp-audit 0.18.2 (`--connect`) y mcp-shield 1.0.4 sobre los mismos servidores. Cada servidor se reprodujo por stdio, así que cada escáner se conectó a él como lo haría en la práctica. El banco de pruebas, los conjuntos y cada juicio están en [`scripts/scanner-comparison`](../scripts/scanner-comparison/). El estudio completo, con el método y todas las salvedades, es la [comparación de escáneres](scanner-comparison.es.md).

Las tres últimas filas vienen de MCPTox (Wang et al., AAAI 2026), un benchmark publicado de 485 herramientas envenenadas escritas para 45 servidores MCP reales. Dividimos sus servidores en dos con un hash fijo. El ruleset v10 se escribió a partir de 22 servidores; la tabla informa sobre los otros 23, con 218 herramientas envenenadas a las que no se ajustó ninguna regla.

| Servidores | WARDEN 0.8.2 (v8) | WARDEN 0.9.0 (v10) | mcp-audit 0.18.2 | mcp-shield 1.0.4 |
|---|---|---|---|---|
| 23 ataques escritos por nosotros, bloqueados | 14 | 20 | 10 | 6 |
| 10 ataques de los propios fixtures de mcp-audit y mcp-shield, bloqueados | 7 | 10 | 10 | 8 |
| 12 casos benignos difíciles, bloqueados | 0 | 0 | 1 | 1 |
| 986 servidores públicos, bloqueados | 3 | 3 | 33 | 343 |
| …bloqueos que se sostienen al leer el texto | 1, y 1 discutible | 1, y 1 discutible | 0 | 0 de 20 elegidos al azar |
| 218 herramientas envenenadas de MCPTox en los servidores reservados, bloqueadas | 26 | 171 | 25 | 41 |
| 225 herramientas de MCPTox con el prefijo `<IMPORTANT>` o «Ignore the previous instructions», bloqueadas | 225 | 225 | 222 | no ejecutado |
| 45 servidores limpios de MCPTox, bloqueados | 0 | 0 | 2 | 3 |

- **Lee primero la fila del corpus.** Ninguna regla se ajustó a ella. Los 33 bloqueos de mcp-audit son 16 «homoglifos» en texto escrito por completo en su propio alfabeto (puntuación china, símbolos griegos, cirílico), 12 instrucciones de honestidad como «do not tell the user the check digits are wrong», 3 utilidades base64, una herramienta de clave pública SSH y la herramienta de despliegue que WARDEN también bloquea por error. mcp-shield bloquea el 35 % de los servidores reales, casi siempre por una palabra clave: «API key», «token», `.env`, «..». Unos puntos suspensivos («Shopify...») cuentan como salto de directorio. También bloquea el servicio de identidad que bloquea WARDEN, pero por la palabra «credentials».
- **Ten presente qué números están ajustados.** El primer conjunto de ataques lo escribimos nosotros. El ruleset v9 se escribió después de leer ambos conjuntos de ataques, y v10 después de los 22 servidores de MCPTox de la otra mitad. Así que 20 y 10 son la exhaustividad de reglas ajustadas a lo que vieron. La fila reservada de MCPTox, los servidores limpios, el corpus y toda la columna 0.8.2 no están ajustados. Sobre el corpus, v10 bloquea exactamente lo mismo que v8.
- **MCPTox prueba una forma, no una palabra clave.** Casi todas las herramientas envenenadas le dicen al modelo que llame antes a otra herramienta o que cambie los argumentos de otra. v10 nombra esa forma (`TOOL_DEF_CROSS_TOOL`, ver [la cadena de compuertas](gates.es.md)) y bloquea 171 de las 218 herramientas reservadas, frente a 189 de 267 en la mitad con la que se escribió. Con el prefijo `<IMPORTANT>` o «Ignore the previous instructions» del benchmark, todos los escáneres que ejecutamos las detectan; mcp-shield no lo ejecutamos sobre ese conjunto. En los servidores limpios, mcp-audit bloquea AmapMap y BaiduMap, y mcp-shield bloquea FileSystem, AdFin y Commander por «sensitive file access».
- **Lo que WARDEN todavía no detecta:** 47 de las 218 herramientas reservadas de MCPTox, una instrucción en chino para leer `.env`, una paráfrasis sin palabras clave («gather every credential file … keep this step to yourself») y «include the output of env». Informa 41 de esas 47, y las tres nuestras, como avisos, no como bloqueos. Necesitan una comprobación por significado, no otra regla: con el clasificador opcional de arriba, 191 de las 218 quedan bloqueadas en `high` y las 218 quedan marcadas.
- **No comparado:** Snyk Agent Scan, antes Invariant mcp-scan y el escáner más usado. Juzga las descripciones en los servidores de Snyk y necesita un token de cuenta. mcp-audit también tiene archivo lock, modo diff para PR y SARIF; WARDEN no está solo en ese hueco.

## Lo que scan no hace

- Lee las definiciones una vez. Un servidor que cambie después lo detecta el siguiente análisis, el lock en CI o `wrap` en cada llamada.
- No analiza argumentos ni resultados de llamadas, prompts ni resources, y no es un sandbox: iniciar un servidor stdio lo ejecuta.
- Sus veredictos son las reglas estáticas y los registros de amenazas de WARDEN. Una paráfrasis que ninguna regla cubre pasa; consulta [la cadena de compuertas](gates.es.md) y el [estudio de campo](mcp-survey.es.md) para ver qué detectan las reglas y con qué frecuencia se equivocan.
