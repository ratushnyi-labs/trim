# trim — Manual do utilizador
> **trim** — Remocao de metadados inertes, independente do alvo

## Pre-requisitos
- Docker Engine 20.10+ ou Docker Desktop
- Docker Compose V2
- Docker Buildx (para compilacoes multi-arquitectura / `dist.sh`)

## Instalacao
### Opcao 1: Binario estatico pre-compilado
Se os binarios distribuiveis foram compilados com `dist.sh`:
```bash
tar -xzf dist/trim-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/trim-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```
Estes sao binarios musl completamente estaticos sem dependencias em tempo de execucao. Funcionam em qualquer distribuicao Linux.

### Opcao 2: Imagem Docker
```bash
git clone <repo-url>
cd trim
docker compose build strip
```
Compilar para uma plataforma especifica:
```bash
docker buildx build --platform linux/arm64 -t trim .
```

## Utilizacao
### Analisar codigo morto (apenas leitura)
```bash
trim --dry-run /path/to/binary
```
### Escrever binario corrigido num ficheiro de saida
```bash
trim /path/to/binary /path/to/output
```
### Escrever binario corrigido para stdout
```bash
trim /path/to/binary > /path/to/output
```
### Pipe: ler de stdin, escrever para stdout
```bash
cat /path/to/binary | trim - > /path/to/output
```
### Modificacao no local
```bash
trim -i /path/to/binary
trim -i /path/to/app1 /path/to/app2
```
### Atraves do Docker
```bash
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```
### Atraves do docker compose
```bash
docker compose run --rm strip -i /work/myapp
```

## Formatos suportados
| Formato | Analisar | Compactar | Arquitecturas | Notas |
|---------|----------|-----------|---------------|-------|
| ELF | Sim | Sim | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Compactacao fisica + correcao de offsets |
| PE/COFF | Sim | Sim | x86-64, x86-32, AArch64, ARM32 | Compactacao fisica + correcao de metadados |
| Mach-O | Sim | Sim | x86-64, AArch64, ARM32 | Compactacao fisica + correcao de load commands |
| .NET | Sim | Sim | IL (independente de arquitectura) | Compactacao de metodos mortos via pipeline PE |
| WebAssembly | Sim | Sim | Wasm | Reconstrucao da seccao de codigo |
| Java .class | Sim | Sim | JVM bytecode | Remocao de metodos mortos |

## Saida
O modo de analise reporta as funcoes mortas encontradas:
```text
analyzing: /work/myapp (20528 bytes)
  found 5 dead functions (230 bytes):
    dead_compute: 53 bytes @ 0x1195
    ...
```
O modo de correcao remove o codigo morto e reporta os bytes libertados:
```text
  reassembled: 5 dead functions removed, 230 bytes freed
```

## Codigos de saida
| Codigo | Significado |
|--------|-------------|
| 0 | Todos os ficheiros processados com sucesso |
| 1 | Um ou mais ficheiros falharam ou com erros |

## Distribuicao
| Plataforma | Arquivo | Alvo |
|------------|---------|------|
| linux/amd64 | trim-linux-amd64.tar.gz | x86_64-unknown-linux-musl |
| linux/arm64 | trim-linux-arm64.tar.gz | aarch64-unknown-linux-musl |

## Resolucao de problemas
- "Permission denied": O ficheiro deve ter permissoes de escrita. Com Docker, faca corresponder o uid do utilizador do contentor com --user $(id -u):$(id -g).
- "not found": O caminho do ficheiro nao existe ou nao e um ficheiro regular.
- "not writable": O ficheiro e apenas de leitura; use chmod u+w para corrigir.
- "skipped": O ficheiro nao e um formato binario reconhecido ou nao tem funcoes para analisar.
