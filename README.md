# RustProxy — идеальный BungeeCord-прокси на Rust

Полноценный сетевой прокси для Minecraft Java Edition, написанный с нуля на Rust под управлением высоких нагрузок (цель — 2000+ реальных игроков на одном прокси, все ядра контейнера Pterodactyl загружены по делу).

## На что он похож

Функционально — полный аналог BungeeCord / Waterfall / Velocity:
- вход (логин) с верной авторизацией (офлайн / онлайн через Mojang Session Server, Microsoft — шаг 2),
- список серверов и пинг (status),
- переключение между серверами (`/server <имя>`),
- проброс трафика клиент ↔ бэкенд,
- поддержка версий **1.16.5 (протокол 754) → 26.3 (протокол 777)**,
- многопоточность на все ядра контейнера (Tokio multi-thread),
- блокировка без блокировки потоков (dashmap, Arc, каналы).

## Состояние (этап 1 — сделано)

- Скелет проекта, конфигурация (`config.toml`).
- Ядро протокола: VarInt, версии 754–777, пакеты Handshake/Status/Login, кадр со zlib-сжатием.
- Авторизация: `offline` (генерация офлайн-UUID, как в Bungee/Velocity) и `online` (проверка профиля через `sessionserver.mojang.com`).
- Сетевой стек: прослушивание порта, рукопожатие, статус (ping), логин, подключение к бэкенду, пайп клиент ↔ бэкенд.
- Мультипоточность: Tokio multi-thread на `worker_threads` ядер (по умолчанию все CPU).
- `/server`, `/ping`, `/proxy`, `/help` на клиентской стороне.

## Сборка

На узле/Pterodactyl нужно поставить Rust:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Собрать и запустить:

```bash
cargo build --release
./target/release/rustproxy -c config.toml
```

Логи управляются через `RUST_LOG` (например `RUST_LOG=rustproxy=debug,info`).

## Конфиг (`config.toml`)

```toml
[proxy]
name = "RustProxy"
motd = "§bRustProxy §f— ideal top proxy"
online_mode = true
max_players = 2000
compression_threshold = 256
default_server = "lobby"

[network]
bind = "0.0.0.0:25565"
worker_threads = 0   # 0 = все ядра

[status]
motd = "§aRustProxy §7| §b1.16.5 → 26.3"
max_players = 2000

[[servers]]
name = "lobby"
address = "127.0.0.1:25566"
enabled = true

[auth]
mode = "online"   # online | offline | microsoft (шаг 2)
```

## Версии Minecraft

| Диапазон | Протоколы |
|---|---|
| 1.16.5 → 1.16.4 | 754 |
| 1.17 → 1.18.2 | 755 → 758 |
| 1.19 → 1.19.4 | 759 → 762 |
| 1.20 → 1.20.6 | 763 → 766 |
| 1.21 → 1.21.6 | 767 → 771 |
| 1.21.7 → 1.21.11 | 772 → 774 |
| 26.1 → 26.3 | 775 → 777 |

Прокси принимает клиентов с любого протокола из диапазона 754–777 и соединяет с бэкендом того же протокола (перевод пакетов между версиями ViaVersion-стиля — шаг 4).

## Дорожная карта (этапы)

1. ✅ Сетка, конфиг, авторизация, ядро протокола 754–777 (этот коммит)
2. Статус/пинг серверов, полноценный логин, проксирование трафика
3. Переключение серверов (`/server`), проброс списка игроков, таймауты
4. ViaVersion-перевод пакетов между версиями, кэш профилей Mojang
5. Microsoft/Xbox авторизация, шифрование connections,压缩 tuning
6. Нагрузочное тестирование 2000 CCU, оптимизация под Pterodactyl
