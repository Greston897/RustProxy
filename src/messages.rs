//! # Красивые сообщения с HEX и multiline (Этап 10)
//!
//! Поддержка:
//!   • &0-&9, &a-&f — классические цвета Minecraft
//!   & #RRGGBB — HEX цвета (Minecraft 1.16+)
//!   &l, &m, &n, &o, &r — форматирование
//!   \n — перенос строки (multiline)
//!   §x + §R§G§B — внутреннее представление HEX в Minecraft
//!
//! Пример:
//!   "&b&lRustProxy &f» &eПривет, &6Игрок! &fТвой баланс: &a$1500"
//!   "&cОшибка: &fНедостаточно прав.\n&7Обратитесь к администрации."

use once_cell::sync::Lazy;
use regex::Regex;

/// Перевести строку с &кодами и HEX в Minecraft-компонент (JSON text).
pub fn format_message(raw: &str) -> String {
    let converted = convert_to_minecraft(raw);
    // Обёртка в JSON-компонент с поддержкой multiline
    let escaped = escape_json(&converted);
    serde_json::json!({
        "text": escaped,
        "color": "reset"
    }).to_string()
}

/// Перевести &коды в §, а & #RRGGBB в §x§R§G§B.
pub fn convert_to_minecraft(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '&' {
            match chars.peek() {
                Some('0') | Some('1') | Some('2') | Some('3') | Some('4') |
                Some('5') | Some('6') | Some('7') | Some('8') | Some('9') |
                Some('a') | Some('b') | Some('c') | Some('d') | Some('e') |
                Some('f') | Some('A') | Some('B') | Some('C') | Some('D') |
                Some('E') | Some('F') | Some('k') | Some('l') | Some('m') |
                Some('n') | Some('o') | Some('r') => {
                    out.push('§');
                    out.push(chars.next().unwrap());
                }
                Some('#') => {
                    chars.next(); // #
                    let mut hex = String::new();
                    for _ in 0..6 {
                        if let Some(c) = chars.peek() {
                            hex.push(*c);
                            chars.next();
                        }
                    }
                    if hex.len() == 6 {
                        // Minecraft HEX: §x§R§G§B
                        out.push('§');
                        out.push('x');
                        for c in hex.chars() {
                            out.push('§');
                            out.push(c);
                        }
                    }
                }
                _ => out.push('&'),
            }
        } else if ch == '\\' {
            // \n → перенос строки
            if let Some('n') = chars.peek() {
                chars.next();
                out.push('\n');
            } else {
                out.push('\\');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Экранирование строки для JSON.
fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
     .replace('"', "\\\"")
     .replace('\n', "\\n")
     .replace('\r', "\\r")
     .replace('\t', "\\t")
}

/// Создать красивый заголовок сервера (MOTD) с HEX.
pub fn server_motd(name: &str, online: usize, max: usize) -> String {
    format!(
        "&b&l{} &f» &eОнлайн: &a{}&f/&a{}",
        name, online, max
    )
}

/// Создать сообщение об ошибке.
pub fn error_message(text: &str) -> String {
    format!("&c&lОШИБКА &f» &c{}", text)
}

/// Создать сообщение об успехе.
pub fn success_message(text: &str) -> String {
    format!("&a&lУСПЕХ &f» &a{}", text)
}

/// Создать информационное сообщение.
pub fn info_message(text: &str) -> String {
    format!("&b&lИНФО &f» &f{}", text)
}

/// Шаблон приветствия при входе.
pub fn welcome_message(username: &str, motd: &str) -> String {
    format!(
        "&b&lRustProxy &f» &fДобро пожаловать, &e{} &f!\n&7{}\n&fИспользуйте &a/help &fдля списка команд.",
        username, motd
    )
}

static HEX_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"&x([0-9a-fA-F]{6})").unwrap());

/// Быстрая замена &xRRGGBB на §x§R§G§B (дляalready processed строк).
pub fn quick_hex(text: &str) -> String {
    HEX_RE.replace_all(text, |caps: &regex::Captures| {
        let hex = &caps[1];
        let mut result = String::from("§x");
        for c in hex.chars() {
            result.push('§');
            result.push(c);
        }
        result
    }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_basic() {
        let out = convert_to_minecraft("&b&lПривет &fМир");
        assert!(out.contains('§'));
        assert!(!out.contains('&'));
    }

    #[test]
    fn convert_hex() {
        let out = convert_to_minecraft("&c&#FF0000Красный");
        assert!(out.contains("§x"));
        assert!(out.contains("§F"));
    }

    #[test]
    fn multiline() {
        let out = convert_to_minecraft("Line1\\nLine2");
        assert!(out.contains('\n'));
    }

    #[test]
    fn json_escape() {
        let j = escape_json("Привет \"мир\"");
        assert!(j.contains("\\\""));
    }
}
