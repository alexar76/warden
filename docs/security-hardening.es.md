# Warden 0.7.0: aprobaciones y verificación continua

> 🌐 [English](security-hardening.md) · [Русский](security-hardening.ru.md) · **Español** · [Français](security-hardening.fr.md) · [中文](security-hardening.zh.md)

Warden 0.7.0 y ARGUS 0.3.2 cierran seis problemas. Se verifican las definiciones y la configuración de arranque; esto no constituye aislamiento del sistema operativo ni una garantía del comportamiento del servidor.

1. **Antes de conectar.** Ejecutar `warden.vetLaunch(server)` antes de iniciar el proceso stdio o abrir el transporte remoto. Comprueba procedencia, amenazas conocidas en comandos/direcciones e identidad de arranque aprobada. Después, obtener todas las páginas de `tools/list` y ejecutar `vet(server, tools)` antes de exponer herramientas al modelo. Aprobar el arranque no aprueba las herramientas.
2. **Protección del feed firmado.** Se guardan timestamp, digest y registros del último snapshot por clave de editor en `feeds/`. Se rechaza un timestamp anterior o contenido distinto con el mismo timestamp, incluso tras reiniciar. Un snapshot firmado posterior puede retirar reglas. Si falla la actualización se mantienen los últimos registros aceptados; `feed.status.stale` informa de su antigüedad por separado. El límite de diez segundos incluye cabeceras y cuerpo completo; siguen vigentes los límites de bytes y registros.
3. **Stdio.** Estructuras JSON-RPC inválidas devuelven `-32600`, parámetros inválidos `-32602` y JSON mal formado `-32700`. UTF-8 se decodifica al recibir la trama completa. Máximo: 1 MiB por trama y 8 KiB por cabecera Content-Length. Una trama inválida o excesiva cierra la conexión deliberadamente; un objeto de solicitud inválido no termina el proceso. Los argumentos mantienen el límite independiente de 256 000 caracteres.
4. **Aprobaciones persistentes.** `vet_mcp_server` consulta pins guardados. `status_mcp_server({server, tools})` devuelve `previous`, `previousRevision`, `currentTools`, `currentToolsHash`, `currentIdentityHash` y `changed` para revisión. Aprobar requiere los hashes exactos revisados y `previous_pin_revision` (null para la primera aprobación). Revocar también exige la revisión anterior. Un cambio concurrente invalida una revisión antigua. Las definiciones se guardan para comparación: no incluir credenciales reales.
5. **Definiciones completas.** El formato v2 incluye todos los campos publicados: `title`, `outputSchema`, `annotations` y extensiones. Se omiten campos superiores undefined. Las definiciones simples name/description/inputSchema conservan su digest. Pins antiguos que no cubrían campos adicionales requieren aprobación explícita (`PIN_FORMAT_UPGRADE_REQUIRED`); los nuevos registran `toolsHashVersion: 2`. Las reglas v6 analizan las superficies adicionales. Las comillas de serialización JSON no convierten una instrucción en una cita inocua. Las anotaciones no conceden permisos.
6. **Sesión activa.** ARGUS pone las herramientas en cuarentena inmediatamente al recibir `notifications/tools/list_changed` y verifica de nuevo todas las páginas. También verifica antes de cada llamada, aunque el servidor omita notificaciones. Una referencia antigua no ejecuta una definición modificada, incluso tras aprobarla de nuevo. Fallos de listado, nombres duplicados, cursores repetidos, más de 32 páginas, 256 herramientas o 1 MiB de definiciones bloquean el uso. No se reaprueban cambios automáticamente. La primera conexión limpia conserva la política existente de ARGUS: guardar automáticamente el primer pin, sin revisión humana implícita. Si falla esa escritura, se cierra la conexión. Un cambio durante la ejecución impide devolver el resultado, pero no deshace efectos ya producidos; no reintentar automáticamente.

## Estado y permisos

Directorio: `WARDEN_STATE_DIR`, en su defecto `$XDG_STATE_HOME/warden`, o `~/.local/state/warden`. La biblioteca acepta `ThreatFeed({stateDir})` y `FilePinStore(directory)`. ARGUS usa `warden/` dentro de su directorio de memoria para el feed. Archivos con nombre derivado del hash del ID, reemplazo atómico, permisos solo del propietario y bloqueos por archivo. Tras una caída con bloqueo activo, la escritura falla de forma segura: detener todos los escritores, inspeccionar y borrar solo el `.lock` abandonado. No borrar snapshots para ocultar errores. Usar almacenamiento local persistente; eliminarlo borra aprobaciones e historial contra rollback.

Las mutaciones MCP están deshabilitadas por defecto. El operador puede establecer `WARDEN_ALLOW_PIN_CHANGES=1` antes de iniciar `warden-mcp`. Esto delega al cliente MCP la capacidad de aprobar/revocar; no puede activarse mediante argumentos. El host o una sesión separada de operador debe imponer la revisión humana. Escanear no aprueba silenciosamente; reaprobaciones deben superar las demás comprobaciones.

## Actualización y límites

Publicar/instalar primero `@aimarket/warden@0.7.0`, después `@alexar76/argus3@0.3.2`, y reiniciar clientes MCP. Revisar migraciones de pins antiguos en vez de borrarlos. Otros hosts deben integrar `vetLaunch` y la revalidación. Cambios de comportamiento con definiciones idénticas no son detectables por hashes. Los resultados siguen siendo datos no confiables: este cambio no añade filtrado de resultados ni aislamiento de procesos. Las pruebas locales cubren rollback, reinicio, timeout del cuerpo, UTF-8 fragmentado, mensajes inválidos, persistencia, cambios de metadatos y bloqueo en ARGUS, sin pagos ni despliegue en producción.

```js
const state = (await client.callTool({
  name: "status_mcp_server", arguments: { server, tools },
})).structuredContent;
// Review state.previous against state.currentTools and the launch identity first.
await client.callTool({ name: "approve_mcp_server", arguments: {
  server, tools,
  reviewed_tools_hash: state.currentToolsHash,
  reviewed_identity_hash: state.currentIdentityHash,
  previous_pin_revision: state.previousRevision,
} });
const verdict = (await client.callTool({
  name: "vet_mcp_server", arguments: { server, tools },
})).structuredContent;
if (!verdict.allow) throw new Error("WARDEN blocked the server");
// Revoke using a freshly reviewed status, not the pre-approval revision.
```
