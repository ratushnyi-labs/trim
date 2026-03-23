# trim — Manuel utilisateur
> **trim** — Suppression de metadonnees inertes, independante de la cible

## Prerequis
- Docker Engine 20.10+ ou Docker Desktop
- Docker Compose V2
- Docker Buildx (pour les builds multi-architecture / `dist.sh`)

## Installation
### Option 1 : Binaire statique preconstruit
Si des binaires distribuables ont ete construits avec `dist.sh` :
```bash
tar -xzf dist/trim-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/trim-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```
Ce sont des binaires entierement statiques bases sur musl, sans aucune dependance d'execution. Ils fonctionnent sur n'importe quelle distribution Linux.

### Option 2 : Image Docker
```bash
git clone <repo-url>
cd trim
docker compose build strip
```
Construire pour une plateforme specifique :
```bash
docker buildx build --platform linux/arm64 -t trim .
```

## Utilisation
### Analyser le code mort (lecture seule)
```bash
trim --dry-run /path/to/binary
```
### Ecrire le binaire corrige dans un fichier de sortie
```bash
trim /path/to/binary /path/to/output
```
### Ecrire le binaire corrige sur stdout
```bash
trim /path/to/binary > /path/to/output
```
### Pipeline : lire depuis stdin, ecrire sur stdout
```bash
cat /path/to/binary | trim - > /path/to/output
```
### Modification sur place
```bash
trim -i /path/to/binary
trim -i /path/to/app1 /path/to/app2
```
### Via Docker
```bash
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```
### Via docker compose
```bash
docker compose run --rm strip -i /work/myapp
```

## Formats pris en charge
| Format | Analyse | Compaction | Architectures | Notes |
|--------|---------|------------|---------------|-------|
| ELF | Oui | Oui | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Compaction physique + correction des offsets |
| PE/COFF | Oui | Oui | x86-64, x86-32, AArch64, ARM32 | Compaction physique + correction des metadonnees |
| Mach-O | Oui | Oui | x86-64, AArch64, ARM32 | Compaction physique + correction des commandes de chargement |
| .NET | Oui | Oui | IL (independant de l'architecture) | Compaction des methodes mortes via le pipeline PE |
| WebAssembly | Oui | Oui | Wasm | Reconstruction de la section de code |
| Java .class | Oui | Oui | JVM bytecode | Suppression des methodes mortes |

## Sortie
Le mode analyse signale les fonctions mortes trouvees :
```text
analyzing: /work/myapp (20528 bytes)
  found 5 dead functions (230 bytes):
    dead_compute: 53 bytes @ 0x1195
    ...
```
Le mode correction supprime le code mort et indique les octets liberes :
```text
  reassembled: 5 dead functions removed, 230 bytes freed
```

## Codes de sortie
| Code | Signification |
|------|---------------|
| 0 | Tous les fichiers ont ete traites avec succes |
| 1 | Un ou plusieurs fichiers ont echoue ou des erreurs sont survenues |

## Distribution
| Plateforme | Archive | Cible |
|------------|---------|-------|
| linux/amd64 | trim-linux-amd64.tar.gz | x86_64-unknown-linux-musl |
| linux/arm64 | trim-linux-arm64.tar.gz | aarch64-unknown-linux-musl |

## Depannage
- "Permission denied" : Le fichier doit etre accessible en ecriture. Avec Docker, faites correspondre l'uid de l'utilisateur du conteneur avec --user $(id -u):$(id -g).
- "not found" : Le chemin du fichier n'existe pas ou n'est pas un fichier regulier.
- "not writable" : Le fichier est en lecture seule ; utilisez chmod u+w pour corriger.
- "skipped" : Le fichier n'est pas un format binaire reconnu ou ne contient aucune fonction a analyser.
