# Log Formatter Examples

## Comparativa Antes y Después

### ANTES (Formato antiguo - poco legible):
```
2025-10-16T15:37:38+02:00 INF Iniciando passive-rec target=booking.avanzabus.com outdir=. tools=[amass subfinder assetfinder rdap crtsh dedupe dnsx waybackurls gau httpx subjs linkfinderevo] workers=64 active=true report=true
2025-10-16T15:37:38+02:00 TRC grupo subdomain-sources: inicio con concurrencia=4, steps=4
2025-10-16T15:37:50+02:00 TRC crtsh booking.avanzabus.com: 30 certificados únicos
2025-10-16T15:38:07+02:00 DBG run: gau booking.avanzabus.com
2025-10-16T15:38:59+02:00 INF pipeline_step duration_ms=11979 end=2025-10-16T15:37:50+02:00 errors={"ok":1} group=cert-sources...
```

### DESPUÉS (Formato nuevo - limpio y colorido):
```
[15:37:38] ✓ [INFO] Iniciando passive-rec
    target: booking.avanzabus.com | workers: 64 | active: true | scope: domain

[15:37:38] • [TRACE] grupo subdomain-sources
    concurrencia: 4 | steps: 4

[15:37:50] ✓ [TRACE] crtsh booking.avanzabus.com: 30 certificados únicos

[15:38:07] → [DEBUG] run: gau booking.avanzabus.com

[15:38:59] ✓ [INFO] pipeline_step
    duration_ms: 11979 | status: ok | outputs: 30 | errors: {"ok":1}
```

## Estructura de Colores

### Niveles de Log con Colores y Símbolos

```
[ERROR]  ✗ Rojo brillante - Errores críticos
[WARN]   ⚠ Amarillo - Advertencias
[INFO]   ✓ Verde - Información importante
[DEBUG]  → Azul - Información de debug
[TRACE]  • Gris tenue - Información de trazabilidad
```

## Ejemplos Detallados

### 1. Log de Inicio (INFO)
```
[15:37:38] ✓ [INFO] Iniciando passive-rec
    target: booking.avanzabus.com | workers: 64 | active: true | scope: domain
    outdir: . | report: true
```

**Características:**
- Timestamp cortado (solo HH:MM:SS)
- Icono verde + verde brillante para importancia
- Parámetros principales en una línea
- Parámetros secundarios en línea separada

### 2. Log de Proceso Exitoso (TRACE)
```
[15:37:38] • [TRACE] checkpoint auto-save started
    interval: 30s
```

**Características:**
- Icono de punto gris (tenue)
- Información de configuración indentada

### 3. Log de Comando Ejecutado (DEBUG)
```
[15:38:07] → [DEBUG] run: gau booking.avanzabus.com
    command: /home/llvch/go/bin/gau
    timeout: 120s | deadline: 2025-10-16T15:40:07+02:00
```

**Características:**
- Icono de flecha azul para proceso
- Detalles del comando en líneas secundarias

### 4. Log de Resultado (INFO)
```
[15:38:13] ✓ [INFO] done: waybackurls
    duration_ms: 5814 | status: ok | lines: 354
```

**Características:**
- Check verde para completación exitosa
- Métrica de duración prominente

### 5. Log de Error (ERROR)
```
[15:38:21] ✗ [ERROR] crtsh query failed
    target: booking.avanzabus.com
    error: Connection timeout
    attempts: 3 | retry_after: 30s
```

**Características:**
- X rojo para error
- Error resaltado
- Información de reintento

### 6. Resumen de Pipeline (INFO con tabla)
```
[15:39:01] ✓ [INFO] orquestador: pipeline ejecutado
    duration: 1m21.443s | steps: 8

    Resultados por tool:
    ├─ crtsh: 30 certificados
    ├─ waybackurls: 354 URLs
    ├─ gau: 365 URLs
    ├─ httpx: 135 hosts vivos
    ├─ subjs: 30 sujetos
    └─ linkfinderevo: 78 rutas
```

## Mejoras Implementadas

### 1. **Claridad Visual**
- Iconos emoji para identificación rápida
- Colores ANSI consistentes
- Timestamps cortos y legibles
- Indentación clara

### 2. **Estructura**
- Línea principal con contexto
- Detalles en líneas indentadas
- Separación clara de niveles
- Campos agrupados lógicamente

### 3. **Performance**
- Fields importantes mostrados primero
- Información secundaria disponible pero oculta en segunda lectura
- Sin información redundante

### 4. **Mantenibilidad**
- Formato consistente en toda la aplicación
- Fácil de parsear para scripts
- Compatible con pipes y redirects

## Uso en Código

### Cambios Mínimos Requeridos
Los logs existentes funcionarán sin cambios. El formatter automáticamente:
1. Interpreta el nivel de log
2. Aplica colores según el nivel
3. Formatea campos de manera legible

### Ejemplo de Uso
```go
// Código existente sigue funcionando
logx.Infof("Iniciando passive-rec target=%s workers=%d", target, workers)

// Con fields estructurados (recomendado)
logx.Info("Pipeline completado", logx.Fields{
    "target": target,
    "duration_ms": 1234,
    "outputs": 100,
    "status": "ok",
})
```

## Configuración

### Habilitar/Deshabilitar Colores
```go
logx.EnableColors(true)  // Habilitar colores
logx.EnableColors(false) // Deshabilitar colores (para logs en archivo)
```

### Cambiar Formato de Timestamp
```go
formatter := logx.GetFormatter()
formatter.SetTimeFormat("15:04:05")      // Más corto
formatter.SetTimeFormat("2006-01-02 15:04:05") // Más largo
```

### Generar Barra de Progreso
```go
formatter := logx.GetFormatter()
bar := formatter.ProgressBar(50, 100) // 50/100
// Output: [██████████░░░░░░░░░░░] 50/100
```

## Compatibilidad

- ✅ Compatible con API existente
- ✅ Sin cambios requeridos en código actual
- ✅ Funciona con piping de logs
- ✅ Respeta niveles de verbosidad existentes
- ✅ Colores se deshabilitan automáticamente en no-TTY
