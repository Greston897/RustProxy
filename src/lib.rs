//! RustProxy — BungeeCord / NullCordX-like Minecraft network proxy on Rust.
//!
//! Этапы:
//! 1. (готово)  Сетка, конфиг, авторизация offline/online, ядро протокола 754→777
//! 2. (готово)  Шифрование логина (RSA+AES/CFB8), кэш Mojang
//! 3. (готово)  Фоновый пинг, таймауты, чистый дисконнект
//! 4. (готово)  ViaVersion перевод пакетов 754↔777
//! 5. (пропуск) Microsoft/Xbox auth
//! 6. (готово)  Оптимизация 2к CCU, connection pool, метрики, graceful shutdown
//! 7. (переработка) Убраны фалш-модули, продакшн-архитектура
//! 8. (сейчас)  Простой auth: /login /register /l /reg + Telegram 2FA + IP-кэш 1ч
//! 9. (сейчас)  CAPTCHA: бот-проверка + ховер-капча + 4ч кэш по аккаунту + IP-смена
//! 10. (сейчас)  Скины (порт SkinsRestorer на Rust)
//! 11. (сейчас)  Аудит безопасности, утечки памяти, уязвимости
//! 12. (планируется) Полный функционал BungeeCord / NullCordX

pub mod auth;
pub mod captcha;
pub mod config;
pub mod ddos_protection;
pub mod fallback;
pub mod metrics;
pub mod messages;
pub mod network;
pub mod protocol;
pub mod proxy;
pub mod skin;
pub mod tfa;
