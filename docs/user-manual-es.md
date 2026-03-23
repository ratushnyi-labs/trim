# trim — Manual de usuario
> **trim** — Eliminacion de metadatos inertes, independiente del objetivo

## Requisitos previos
- Docker Engine 20.10+ o Docker Desktop
- Docker Compose V2
- Docker Buildx (para compilaciones multi-arquitectura / `dist.sh`)

## Instalacion
### Opcion 1: Binario estatico precompilado
Si los binarios distribuibles se han compilado con `dist.sh`:
```bash
tar -xzf dist/trim-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/trim-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```
Estos son binarios musl completamente estaticos sin dependencias en tiempo de ejecucion. Funcionan en cualquier distribucion Linux.

### Opcion 2: Imagen Docker
```bash
git clone <repo-url>
cd trim
docker compose build strip
```
Compilar para una plataforma especifica:
```bash
docker buildx build --platform linux/arm64 -t trim .
```

## Uso
### Analizar codigo muerto (solo lectura)
```bash
trim --dry-run /path/to/binary
```
### Escribir binario parcheado en archivo de salida
```bash
trim /path/to/binary /path/to/output
```
### Escribir binario parcheado en stdout
```bash
trim /path/to/binary > /path/to/output
```
### Pipe: leer de stdin, escribir en stdout
```bash
cat /path/to/binary | trim - > /path/to/output
```
### Modificacion en el lugar
```bash
trim -i /path/to/binary
trim -i /path/to/app1 /path/to/app2
```
### Mediante Docker
```bash
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```
### Mediante docker compose
```bash
docker compose run --rm strip -i /work/myapp
```

## Formatos soportados
| Formato | Analizar | Compactar | Arquitecturas | Notas |
|---------|----------|-----------|---------------|-------|
| ELF | Si | Si | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Compactacion fisica + correccion de offsets |
| PE/COFF | Si | Si | x86-64, x86-32, AArch64, ARM32 | Compactacion fisica + correccion de metadatos |
| Mach-O | Si | Si | x86-64, AArch64, ARM32 | Compactacion fisica + correccion de load commands |
| .NET | Si | Si | IL (independiente de arquitectura) | Compactacion de metodos muertos via pipeline PE |
| WebAssembly | Si | Si | Wasm | Reconstruccion de seccion de codigo |
| Java .class | Si | Si | JVM bytecode | Eliminacion de metodos muertos |

## Salida
El modo de analisis informa las funciones muertas encontradas:
```text
analyzing: /work/myapp (20528 bytes)
  found 5 dead functions (230 bytes):
    dead_compute: 53 bytes @ 0x1195
    ...
```
El modo de parcheo elimina el codigo muerto e informa los bytes liberados:
```text
  reassembled: 5 dead functions removed, 230 bytes freed
```

## Codigos de salida
| Codigo | Significado |
|--------|-------------|
| 0 | Todos los archivos procesados correctamente |
| 1 | Uno o mas archivos fallaron o con errores |

## Distribucion
| Plataforma | Archivo | Objetivo |
|------------|---------|----------|
| linux/amd64 | trim-linux-amd64.tar.gz | x86_64-unknown-linux-musl |
| linux/arm64 | trim-linux-arm64.tar.gz | aarch64-unknown-linux-musl |

## Solucion de problemas
- "Permission denied": El archivo debe tener permisos de escritura. Con Docker, haga coincidir el uid del usuario del contenedor con --user $(id -u):$(id -g).
- "not found": La ruta del archivo no existe o no es un archivo regular.
- "not writable": El archivo es de solo lectura; use chmod u+w para solucionarlo.
- "skipped": El archivo no es un formato binario reconocido o no tiene funciones para analizar.
