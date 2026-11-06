//! RustProxy — BungeeCord / NullCordX-like Minecraft network proxy on Rust.
//!
//! Этапы:
//! 1. (готово)  Сетка, конфиг, авторизация offline/online, ядро протокола 754→777
//! 2. (готово)  Шифрование логина (RSA+AES/CFB8), кэш Mojang
//! 3. (готово)  Фоновый пинг, таймауты, чистый дисконнект
//! 4. (готово)  ViaVersion перевод пакетов 754↔777
//! 5. (пропуск) Microsoft/Xbox auth
//! 6. (готово)  Оптимизация 2к CCU, connection pool, метрики, graceful shutdown
//! 7. (готово)  Убраны фалш-модули, продакшн-архитектура
//! 8. (готово)  Простой auth: /login /register /l /reg + IP-кэш 1ч
//! 9. (готово)  CAPTCHA: бот-проверка + ховер-капча + 4ч кэш по аккаунту + IP-смена
//! 10. (сейчас) TFA через Telegram /link + подтверждение входа через бота
//! 11. (готово)  DDoS защита NBT-пакетами
//! 12. (сейчас)  Этап 15: мониторинг ресурсов бэкендов (NullCordX) + все команды BungeeCord
//!             + система соединений [connect]/[server] в лобби (Velocity/NullCord стиль)

pub mod auth;
pub mod ban;
pub mod backend_monitor;
pub mod captcha;
pub mod config;
pub mod ddos_protection;
pub mod fallback;
pub mod metrics;
pub mod messages;
pub mod network;
pub mod protocol;
pub mod proxy;
pub mod tfa;
