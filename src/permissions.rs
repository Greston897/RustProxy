//! # Система прав доступа (permissions) для команд
//!
//! Права выдаются на каждую команду отдельно игроку.
//! Базовый набор выдаётся всем при регистрации.
//!
//! Базовые права (у всех по умолчанию):
//!   command.server   — /server, /hub, /lobby
//!   command.login    — /login /l, /logout
//!   command.register — /reg /register
//!   command.link     — /link
//!   command.tfa      — /tfa
//!   command.captcha  — /captcha
//!   command.ping     — /ping
//!   command.help     — /help
//!   command.find     — /find
//!   command.serverlist — /serverlist
//!   command.proxy    — /proxy
//!
//! Админские права (только по назначению через /perm):
//!   command.alert    — /alert
//!   command.admin    — /auth (управление аккаунтами)
//!   command.perm     — /perm (выдача прав)

use dashmap::DashMap;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Permission {
    CommandServer,
    CommandHub,
    CommandLogin,
    CommandRegister,
    CommandLink,
    CommandTfa,
    CommandCaptcha,
    CommandPing,
    CommandHelp,
    CommandFind,
    CommandServerList,
    CommandProxy,
    CommandAlert,
    CommandAdmin,
    CommandPerm,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::CommandServer => "command.server",
            Permission::CommandHub => "command.hub",
            Permission::CommandLogin => "command.login",
            Permission::CommandRegister => "command.register",
            Permission::CommandLink => "command.link",
            Permission::CommandTfa => "command.tfa",
            Permission::CommandCaptcha => "command.captcha",
            Permission::CommandPing => "command.ping",
            Permission::CommandHelp => "command.help",
            Permission::CommandFind => "command.find",
            Permission::CommandServerList => "command.serverlist",
            Permission::CommandProxy => "command.proxy",
            Permission::CommandAlert => "command.alert",
            Permission::CommandAdmin => "command.admin",
            Permission::CommandPerm => "command.perm",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "command.server" => Some(Self::CommandServer),
            "command.hub" => Some(Self::CommandHub),
            "command.login" => Some(Self::CommandLogin),
            "command.register" => Some(Self::CommandRegister),
            "command.link" => Some(Self::CommandLink),
            "command.tfa" => Some(Self::CommandTfa),
            "command.captcha" => Some(Self::CommandCaptcha),
            "command.ping" => Some(Self::CommandPing),
            "command.help" => Some(Self::CommandHelp),
            "command.find" => Some(Self::CommandFind),
            "command.serverlist" => Some(Self::CommandServerList),
            "command.proxy" => Some(Self::CommandProxy),
            "command.alert" => Some(Self::CommandAlert),
            "command.admin" => Some(Self::CommandAdmin),
            "command.perm" => Some(Self::CommandPerm),
            _ => None,
        }
    }
}

/// Базовый набор прав — выдаётся всем аккаунтам при регистрации.
pub fn default_permissions() -> HashSet<Permission> {
    let mut set = HashSet::new();
    set.insert(Permission::CommandServer);
    set.insert(Permission::CommandHub);
    set.insert(Permission::CommandLogin);
    set.insert(Permission::CommandRegister);
    set.insert(Permission::CommandLink);
    set.insert(Permission::CommandTfa);
    set.insert(Permission::CommandCaptcha);
    set.insert(Permission::CommandPing);
    set.insert(Permission::CommandHelp);
    set.insert(Permission::CommandFind);
    set.insert(Permission::CommandServerList);
    set.insert(Permission::CommandProxy);
    set
}

/// Менеджер прав.
pub struct PermissionManager {
    /// username → набор прав
    pub permissions: DashMap<String, HashSet<Permission>>,
}

impl PermissionManager {
    pub fn new() -> Self {
        Self { permissions: DashMap::new() }
    }

    /// Выдать право игроку.
    pub fn grant(&self, username: &str, perm: Permission) {
        self.permissions.entry(username.to_string()).or_default().insert(perm);
    }

    /// Забрать право у игрока.
    pub fn revoke(&self, username: &str, perm: Permission) {
        if let Some(perms) = self.permissions.get_mut(username) {
            perms.remove(&perm);
        }
    }

    /// Выдать базовые права при регистрации.
    pub fn grant_default(&self, username: &str) {
        for perm in default_permissions() {
            self.permissions.entry(username.to_string()).or_default().insert(perm);
        }
    }

    /// Проверить, есть ли право.
    pub fn has(&self, username: &str, perm: Permission) -> bool {
        self.permissions.get(username).map(|p| p.contains(perm)).unwrap_or(false)
    }

    /// Получить все права игрока.
    pub fn get(&self, username: &str) -> HashSet<Permission> {
        self.permissions.get(username).map(|p| p.clone()).unwrap_or_default()
    }

    /// Список игроков с конкретным правом.
    pub fn players_with(&self, perm: Permission) -> Vec<String> {
        self.permissions.iter()
            .filter(|e| e.value().contains(&perm))
            .map(|e| e.key().clone())
            .collect()
    }
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_grant_revoke() {
        let mgr = PermissionManager::new();
        assert!(mgr.has("player", Permission::CommandServer));
        assert!(!mgr.has("player", Permission::CommandAdmin));

        mgr.grant("player", Permission::CommandAdmin);
        assert!(mgr.has("player", Permission::CommandAdmin));

        mgr.revoke("player", Permission::CommandAdmin);
        assert!(!mgr.has("player", Permission::CommandAdmin));
    }
}
