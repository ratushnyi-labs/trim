# trim — Посібник користувача

> **trim** — Платформо-незалежне видалення неактивних метаданих

## Передумови

- Docker Engine 20.10+ або Docker Desktop
- Docker Compose V2
- Docker Buildx (для мультиархітектурних збірок / `dist.sh`)

## Встановлення

### Варіант 1: Готовий статичний бінарний файл

Якщо бінарні файли для розповсюдження було зібрано за допомогою `dist.sh`:

```bash
# Розпакуйте бінарний файл для вашої архітектури
tar -xzf dist/trim-linux-amd64.tar.gz -C /usr/local/bin/   # x86_64
tar -xzf dist/trim-linux-arm64.tar.gz -C /usr/local/bin/   # aarch64
```

Це повністю статичні musl-бінарники без жодних залежностей під час виконання.
Вони працюють на будь-якому дистрибутиві Linux.

### Варіант 2: Docker-образ

```bash
git clone <repo-url>
cd trim
docker compose build strip
```

Збірка для конкретної платформи:

```bash
docker buildx build --platform linux/arm64 -t trim .
```

## Використання

### Аналіз мертвого коду (лише читання)

```bash
trim --dry-run /path/to/binary
```

### Запис пропатченого бінарника у вихідний файл

```bash
trim /path/to/binary /path/to/output
```

### Запис пропатченого бінарника у stdout

```bash
trim /path/to/binary > /path/to/output
```

### Конвеєр: читання зі stdin, запис у stdout

```bash
cat /path/to/binary | trim - > /path/to/output
```

### Модифікація на місці

```bash
trim -i /path/to/binary
trim -i /path/to/app1 /path/to/app2
```

### Через Docker

```bash
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip -i /work/myapp
docker run --rm -v $(pwd)/myapp:/work/myapp trim-strip --dry-run /work/myapp
docker run --rm -i trim-strip - < myapp > myapp.patched
```

### Через docker compose

```bash
docker compose run --rm strip -i /work/myapp
```

## Підтримувані формати

| Формат | Аналіз | Компактування | Архітектури | Примітки |
|--------|--------|---------------|-------------|----------|
| ELF | Так | Так | x86-64, x86-32, AArch64, ARM32, RISC-V, MIPS, s390x, LoongArch64 | Фізичне компактування + патчинг зміщень |
| PE/COFF | Так | Так | x86-64, x86-32, AArch64, ARM32 | Фізичне компактування + патчинг метаданих |
| Mach-O | Так | Так | x86-64, AArch64, ARM32 | Фізичне компактування + патчинг load-команд |
| .NET | Так | Так | IL (незалежний від архітектури) | Компактування мертвих методів через PE-конвеєр |
| WebAssembly | Так | Так | Wasm | Перебудова секції коду |
| Java .class | Так | Так | JVM bytecode | Видалення мертвих методів |

## Вивід

Режим аналізу повідомляє про знайдені мертві функції:

```text
analyzing: /work/myapp (20528 bytes)
  found 5 dead functions (230 bytes):
    dead_compute: 53 bytes @ 0x1195
    dead_factorial: 43 bytes @ 0x11d7
    ...
```

Режим патчингу видаляє мертвий код і повідомляє про звільнені байти:

```text
  reassembled: 5 dead functions removed, 230 bytes freed
```

## Коди завершення

| Код | Значення |
|-----|----------|
| 0 | Усі файли оброблено успішно |
| 1 | Один або більше файлів завершились з помилкою |

## Розповсюдження

| Платформа | Архів | Ціль |
|-----------|-------|------|
| `linux/amd64` | `trim-linux-amd64.tar.gz` | `x86_64-unknown-linux-musl` |
| `linux/arm64` | `trim-linux-arm64.tar.gz` | `aarch64-unknown-linux-musl` |

## Усунення несправностей

- **"Permission denied":** Файл має бути доступним для запису. При використанні Docker
  узгодьте uid користувача контейнера за допомогою `--user $(id -u):$(id -g)`.
- **"not found":** Шлях до файлу не існує або це не звичайний файл.
- **"not writable":** Файл доступний лише для читання; виправте за допомогою `chmod u+w`.
- **"skipped":** Файл не є розпізнаним бінарним форматом або не містить
  функцій для аналізу.
