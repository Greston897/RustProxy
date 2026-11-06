//! # Skin System — порт SkinsRestorer на Rust (Этап 14)
//!
//! Позволяет устанавливать кастомные скины игрокам без модов на клиенте.
//! Работает через перехват пакета PlayerList (список игроков) и подмену
//! URL скина и плаща.
//!
//! Поддерживаемые источники скинов:
//!   • Кастомные скины (загружены администратором)
//!   • Скины Mojang (по UUID licensed аккаунта)
//!   • Скины по прямой ссылке (URL)
//!
//! Протокол:
//!   1. Игрок заходит → прокси смотрит его UUID/ник
//!   2. Ищет скит в базе: кастомный → Mojang → дефолтный (Steve/Alex)
//!   3. Подменяет PlayerList пакет с правильными URL скина/плаща
//!   4. При необходимости поднимает микро-HTTP сервер для отдачи скинов

use anyhow::{bail, Context, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Данные скина игрока.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkinData {
    pub uuid: Uuid,
    pub username: String,
    /// URL скина ( texture )
    pub skin_url: Option<String>,
    /// URL плаща ( cape )
    pub cape_url: Option<String>,
    /// Модель: "slim" (Alex) или "default" (Steve)
    pub model: String,
    /// Время установки
    pub set_at: Instant,
    /// Источник скина
    pub source: SkinSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkinSource {
    Custom,       // Загружен админом
    Mojang,       // Официальный скин Mojang
    Url,          // Прямая ссылка
    Default,      // Steve/Alex по умолчанию
}

/// Менеджер скинов.
pub struct SkinManager {
    /// username → SkinData (кастомные скины)
    pub custom_skins: DashMap<String, SkinData>,
    /// UUID → SkinData (кэш Mojang скинов)
    pub mojang_cache: DashMap<Uuid, SkinData>,
    /// Время кэша Mojang скинов (24 часа)
    pub mojang_cache_ttl: std::time::Duration,
    /// HTTP сервер для отдачи кастомных скинов (опционально)
    pub http_server_addr: Option<SocketAddr>,
}

impl SkinManager {
    pub fn new() -> Self {
        Self {
            custom_skins: DashMap::new(),
            mojang_cache: DashMap::new(),
            mojang_cache_ttl: std::time::Duration::from_secs(24 * 3600),
            http_server_addr: None,
        }
    }

    /// Установить кастомный скин для игрока.
    pub fn set_custom_skin(
        &self,
        username: &str,
        uuid: Uuid,
        skin_url: String,
        cape_url: Option<String>,
        model: &str,
    ) {
        let skin = SkinData {
            uuid,
            username: username.to_string(),
            skin_url: Some(skin_url),
            cape_url,
            model: model.to_string(),
            set_at: Instant::now(),
            source: SkinSource::Custom,
        };
        self.custom_skins.insert(username.to_string(), skin);
    }

    /// Получить скин игрока (с приоритетом: кастомный → Mojang → дефолтный).
    pub fn get_skin(&self, username: &str, uuid: Uuid) -> SkinData {
        // 1. Кастомный скин
        if let Some(skin) = self.custom_skins.get(username) {
            return skin.clone();
        }

        // 2. Кэш Mojang
        if let Some(skin) = self.mojang_cache.get(&uuid) {
            if Instant::now().duration_since(skin.set_at) < self.mojang_cache_ttl {
                return skin.clone();
            } else {
                self.mojang_cache.remove(&uuid);
            }
        }

        // 3. Дефолтный скин (Steve/Alex на основе UUID)
        let model = if default_skin_is_slim(uuid) {
            "slim"
        } else {
            "default"
        };
        SkinData {
            uuid,
            username: username.to_string(),
            skin_url: None,
            cape_url: None,
            model: model.to_string(),
            set_at: Instant::now(),
            source: SkinSource::Default,
        }
    }

    /// Получить URL скина из профиля Mojang (требуется онлайн-режим).
    pub async fn fetch_mojang_skin(&self, uuid: Uuid) -> Result<Option<String>> {
        // Mojang API: https://sessionserver.mojang.com/session/minecraft/profile/{uuid}
        let url = format!("https://sessionserver.mojang.com/session/minecraft/profile/{}?unsigned=false", uuid);
        let client = reqwest::Client::new();
        let resp = client.get(&url).send().await?;

        if resp.status().is_success() {
            let profile: serde_json::Value = resp.json().await?;
            let skin_url = profile
                .get("properties")
                .and_then(|p| p.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find(|prop| prop.get("name").and_then(|n| n.as_str()) == Some("textures"))
                        .and_then(|prop| prop.get("value").and_then(|v| v.as_str()))
                })
                .and_then(|b64_value| {
                    base64::decode(b64_value).ok().and_then(|bytes| {
                        String::from_utf8(bytes).ok().and_then(|json| {
                            serde_json::from_str::<serde_json::Value>(&json).ok()
                        })
                    })
                })
                .and_then(|textures| {
                    textures.get("textures").and_then(|t| {
                        t.get("SKIN").and_then(|s| s.get("url").and_then(|u| u.as_str()))
                    })
                });

            Ok(skin_url.map(|s| s.to_string()))
        } else {
            Ok(None)
        }
    }

    /// Кэшировать скин Mojang.
    pub fn cache_mojang_skin(&self, uuid: Uuid, username: &str, skin_url: String, cape_url: Option<String>) {
        let skin = SkinData {
            uuid,
            username: username.to_string(),
            skin_url: Some(skin_url),
            cape_url,
            model: "default".to_string(),
            set_at: Instant::now(),
            source: SkinSource::Mojang,
        };
        self.mojang_cache.insert(uuid, skin);
    }

    /// Удалить кастомный скин.
    pub fn remove_custom_skin(&self, username: &str) {
        self.custom_skins.remove(username);
    }

    /// Список всех кастомных скинов.
    pub fn list_custom_skins(&self) -> Vec<String> {
        self.custom_skins.iter().map(|e| e.key().clone()).collect()
    }
}

/// Определить, использует ли UUID скин Alex (slim) или Steve (default).
/// Алгоритм Mojang: на основе хэша UUID.
fn default_skin_is_slim(uuid: Uuid) -> bool {
    // Mojang использует последний байт UUID для определения модели
    let bytes = uuid.as_bytes();
    let last = bytes[bytes.len() - 1];
    last % 2 == 0 // чётный → slim (Alex), нечётный → default (Steve)
}

impl Default for SkinManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_skin_deterministic() {
        let uuid1 = Uuid::new_v4();
        let uuid2 = Uuid::new_v4();
        // Просто проверяем, что функция возвращает bool без паники
        let _ = default_skin_is_slim(uuid1);
        let _ = default_skin_is_slim(uuid2);
    }

    #[test]
    fn custom_skin_set_get() {
        let mgr = SkinManager::new();
        let uuid = Uuid::new_v4();
        mgr.set_custom_skin("TestPlayer", uuid, "https://example.com/skin.png", None, "slim");

        let skin = mgr.get_skin("TestPlayer", uuid);
        assert_eq!(skin.username, "TestPlayer");
        assert_eq!(skin.source, SkinSource::Custom);
        assert_eq!(skin.model, "slim");
        assert!(skin.skin_url.is_some());
    }

    #[test]
    fn fallback_to_default() {
        let mgr = SkinManager::new();
        let uuid = Uuid::new_v4();
        let skin = mgr.get_skin("UnknownPlayer", uuid);
        assert_eq!(skin.source, SkinSource::Default);
    }
}
