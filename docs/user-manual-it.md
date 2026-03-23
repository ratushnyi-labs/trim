# trim — Manuale utente
> **trim** — Rimozione di metadati inerti, indipendente dal target

## Prerequisiti
- Docker Engine 20.10+ o Docker Desktop
- Docker Compose V2
- Docker Buildx (per build multi-architettura / `dist.sh`)

## Installazione
### Opzione 1: Binario statico precompilato
Se i binari distribuibili sono stati compilati con `dist.sh`:
```bash
tar -xzf dist/trim-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/trim-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```
Questi sono binari musl completamente statici senza dipendenze a runtime. Funzionano su qualsiasi distribuzione Linux.

### Opzione 2: Immagine Docker
```bash
git clone <repo-url>
cd trim
docker compose build strip
```
Compilare per una piattaforma specifica:
```bash
docker buildx build --platform linux/arm64 -t trim .
```

## Utilizzo
### Analizzare codice morto (sola lettura)
```bash
trim --dry-run /path/to/binary
```
### Scrivere il binario corretto in un file di output
```bash
trim /path/to/binary /path/to/output
```
### Scrivere il binario corretto su stdout
```bash
trim /path/to/binary > /path/to/output
```
### Pipe: leggere da stdin, scrivere su stdout
```bash
cat /path/to/binary | trim - > /path/to/output
```
### Modifica sul posto
```bash
trim -i /path/to/binary
trim -i /path/to/app1 /path/to/app2
```
### Tramite Docker
```bash
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```
### Tramite docker compose
```bash
docker compose run --rm strip -i /work/myapp
```

## Formati supportati
| Formato | Analizzare | Compattare | Architetture | Note |
|---------|------------|------------|--------------|------|
| ELF | Si | Si | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Compattazione fisica + correzione degli offset |
| PE/COFF | Si | Si | x86-64, x86-32, AArch64, ARM32 | Compattazione fisica + correzione dei metadati |
| Mach-O | Si | Si | x86-64, AArch64, ARM32 | Compattazione fisica + correzione dei load command |
| .NET | Si | Si | IL (indipendente dall'architettura) | Compattazione dei metodi morti tramite pipeline PE |
| WebAssembly | Si | Si | Wasm | Ricostruzione della sezione di codice |
| Java .class | Si | Si | JVM bytecode | Rimozione dei metodi morti |

## Output
La modalita di analisi riporta le funzioni morte trovate:
```text
analyzing: /work/myapp (20528 bytes)
  found 5 dead functions (230 bytes):
    dead_compute: 53 bytes @ 0x1195
    ...
```
La modalita di correzione rimuove il codice morto e riporta i byte liberati:
```text
  reassembled: 5 dead functions removed, 230 bytes freed
```

## Codici di uscita
| Codice | Significato |
|--------|-------------|
| 0 | Tutti i file elaborati con successo |
| 1 | Uno o piu file hanno avuto errori |

## Distribuzione
| Piattaforma | Archivio | Obiettivo |
|-------------|----------|-----------|
| linux/amd64 | trim-linux-amd64.tar.gz | x86_64-unknown-linux-musl |
| linux/arm64 | trim-linux-arm64.tar.gz | aarch64-unknown-linux-musl |

## Risoluzione dei problemi
- "Permission denied": Il file deve avere i permessi di scrittura. Con Docker, far corrispondere l'uid dell'utente del container con --user $(id -u):$(id -g).
- "not found": Il percorso del file non esiste o non e un file regolare.
- "not writable": Il file e in sola lettura; usare chmod u+w per risolvere.
- "skipped": Il file non e un formato binario riconosciuto o non ha funzioni da analizzare.
