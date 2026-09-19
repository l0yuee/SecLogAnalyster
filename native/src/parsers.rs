//! Conservative native equivalents of the existing webaccess and IIS parsers.
//! Unsupported shapes request an entire-source rollback, never row omission.
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::lines::python_whitespace;
use crate::{Failure, Row, COLUMN_COUNT};

fn regex() -> &'static Regex {
    static CLF: OnceLock<Regex> = OnceLock::new();
    CLF.get_or_init(|| Regex::new(r#"^(?P<client_ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?"#).expect("static CLF expression"))
}

pub fn web(line: &str, max_digits: usize) -> Result<Option<Row>, Failure> {
    if line.contains('\u{1f}') {
        return Err(Failure::Unsupported(
            "CLF contains Python-specific whitespace".into(),
        ));
    }
    let Some(captures) = regex().captures(line) else {
        return Ok(None);
    };
    let mut row = base();
    row.values[2] = web_time(&captures["time"])?;
    row.values[3] = Some(captures["client_ip"].to_owned());
    let request = &captures["request"];
    let mut parts = request.split(' ');
    let uri = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(method), Some(uri), Some(protocol), None) => {
            row.values[6] = Some(method.into());
            row.values[9] = Some(protocol.into());
            Some(uri)
        }
        (Some(method), Some(uri), None, None) => {
            row.values[6] = Some(method.into());
            Some(uri)
        }
        _ if !request.is_empty() && request != "-" => Some(request),
        _ => None,
    };
    if let Some(uri) = uri {
        let (stem, query) = uri.split_once('?').map_or((uri, ""), |pair| pair);
        row.values[7] = nonempty(stem);
        row.values[8] = nonempty(query);
    }
    row.values[10] = Some(
        integer(&captures["status"], max_digits)?
            .ok_or_else(|| Failure::Parse("invalid status integer".into()))?,
    );
    row.numeric[10] = true;
    let bytes = &captures["bytes"];
    if bytes != "-" {
        row.values[13] = Some(integer(bytes, max_digits)?.ok_or_else(|| {
            Failure::Parse(format!("invalid literal for int() with base 10: {bytes:?}"))
        })?);
        row.numeric[13] = true;
    }
    let user = &captures["user"];
    if user != "-" && !user.is_empty() {
        row.values[16] = Some(user.into());
    }
    row.values[17] = captures
        .name("user_agent")
        .map(|value| value.as_str().into());
    row.values[18] = captures.name("referer").and_then(|value| {
        if value.as_str() == "-" {
            None
        } else {
            Some(value.as_str().into())
        }
    });
    Ok(Some(row))
}

pub struct IisLayout {
    field_count: usize,
    fields: Vec<(usize, Option<(usize, bool)>, Option<String>)>,
    date: Option<usize>,
    time: Option<usize>,
}

impl IisLayout {
    pub fn new(header: &str) -> Result<Self, Failure> {
        let fields: Vec<&str> = header
            .split(python_whitespace)
            .filter(|part| !part.is_empty())
            .take(4097)
            .collect();
        if fields.len() > 4096 {
            return Err(Failure::Unsupported(
                "IIS header exceeds native field-count bound".into(),
            ));
        }
        // Compile changing headers once. dict(zip(...)) keeps first-key order
        // but uses the last occurrence, so preserve that ordering for extra JSON.
        let mut unique: Vec<(&str, usize)> = Vec::with_capacity(fields.len());
        let mut positions: HashMap<&str, usize> = HashMap::with_capacity(fields.len());
        for (index, field) in fields.iter().enumerate() {
            if let Some(position) = positions.get(field).copied() {
                unique[position].1 = index;
            } else {
                positions.insert(*field, unique.len());
                unique.push((field, index));
            }
        }
        let date = unique
            .iter()
            .find(|pair| pair.0 == "date")
            .map(|pair| pair.1);
        let time = unique
            .iter()
            .find(|pair| pair.0 == "time")
            .map(|pair| pair.1);
        let layout = unique
            .into_iter()
            .filter(|(name, _)| *name != "date" && *name != "time")
            .map(|(name, index)| {
                let mapped = field_index(name);
                (
                    index,
                    mapped,
                    if mapped.is_none() {
                        Some(json_ascii(name))
                    } else {
                        None
                    },
                )
            })
            .collect();
        Ok(Self {
            field_count: fields.len(),
            fields: layout,
            date,
            time,
        })
    }
}

pub fn iis(line: &str, fields: &IisLayout, max_digits: usize) -> Result<Option<Row>, Failure> {
    let parts: Vec<&str> = line.split(' ').take(fields.field_count + 1).collect();
    if parts.len() != fields.field_count {
        return Ok(None);
    }
    let mut row = base();
    let date = fields.date.map(|index| parts[index]);
    let time = fields.time.map(|index| parts[index]);
    if let (Some(date), Some(time)) = (date, time) {
        if !date.is_empty() && !time.is_empty() && date != "-" && time != "-" {
            row.values[2] = iis_time(date, time)?;
        }
    }
    let mut extra = String::new();
    for (source, mapped, extra_key) in &fields.fields {
        let value = parts[*source];
        let value = if value == "-" { None } else { Some(value) };
        if let Some((index, numeric)) = *mapped {
            row.numeric[index] = numeric;
            row.values[index] = if numeric {
                match value {
                    Some(value) => integer(value, max_digits)?,
                    None => None,
                }
            } else {
                value.map(str::to_owned)
            };
        } else {
            if extra.is_empty() {
                extra.push('{');
            } else {
                extra.push_str(", ");
            }
            extra.push_str(extra_key.as_deref().expect("unknown key"));
            extra.push_str(": ");
            match value {
                Some(value) => extra.push_str(&json_ascii(value)),
                None => extra.push_str("null"),
            }
        }
    }
    if !extra.is_empty() {
        extra.push('}');
        row.values[19] = Some(extra);
    }
    Ok(Some(row))
}

fn field_index(field: &str) -> Option<(usize, bool)> {
    Some(match field {
        "s-ip" => (4, false),
        "cs-method" => (6, false),
        "cs-uri-stem" => (7, false),
        "cs-uri-query" => (8, false),
        "s-port" => (5, false),
        "cs-username" => (16, false),
        "c-ip" => (3, false),
        "cs(User-Agent)" => (17, false),
        "cs(Referer)" => (18, false),
        "sc-status" => (10, true),
        "sc-substatus" => (11, true),
        "sc-win32-status" => (12, true),
        "time-taken" => (15, true),
        "sc-bytes" => (13, true),
        "cs-bytes" => (14, true),
        "cs-version" => (9, false),
        _ => return None,
    })
}

fn base() -> Row {
    Row {
        values: std::array::from_fn(|_| None),
        numeric: [false; COLUMN_COUNT],
    }
}

fn nonempty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.into())
    }
}

// Canonical spelling of an ASCII Python int without narrowing to a machine integer.
fn integer(raw: &str, max_digits: usize) -> Result<Option<String>, Failure> {
    if !raw.is_ascii() {
        return Err(Failure::Unsupported(
            "non-ASCII integer needs Python semantics".into(),
        ));
    }
    // int() uses the six ASCII whitespace bytes, not str.strip()'s broader
    // U+001C..U+001F classification. In particular U+001F can occur inside an
    // IIS value because it is not a physical splitlines delimiter.
    let raw = raw.trim_matches(|character| {
        matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}')
    });
    let (negative, digits) = if let Some(rest) = raw.strip_prefix('-') {
        (true, rest)
    } else {
        (false, raw.strip_prefix('+').unwrap_or(raw))
    };
    if digits.is_empty() {
        return Ok(None);
    }
    let mut previous_digit = false;
    let mut normalized = String::with_capacity(digits.len());
    for byte in digits.bytes() {
        if byte.is_ascii_digit() {
            normalized.push(byte as char);
            previous_digit = true;
        } else if byte == b'_' && previous_digit {
            previous_digit = false;
        } else {
            return Ok(None);
        }
    }
    if !previous_digit || (max_digits != 0 && normalized.len() > max_digits) {
        return Ok(None);
    }
    let nonzero = normalized.trim_start_matches('0');
    Ok(Some(if nonzero.is_empty() {
        "0".into()
    } else if negative {
        format!("-{nonzero}")
    } else {
        nonzero.into()
    }))
}

fn web_time(raw: &str) -> Result<Option<String>, Failure> {
    let bytes = raw.as_bytes();
    if !raw.is_ascii()
        || bytes.len() != 26
        || bytes[2] != b'/'
        || bytes[6] != b'/'
        || bytes[11] != b':'
        || bytes[14] != b':'
        || bytes[17] != b':'
        || bytes[20] != b' '
        || !matches!(bytes[21], b'+' | b'-')
    {
        return Err(Failure::Unsupported(
            "CLF timestamp requires Python strptime fallback".into(),
        ));
    }
    let month = match &raw[3..6] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => {
            return Err(Failure::Unsupported(
                "CLF locale month requires Python strptime fallback".into(),
            ))
        }
    };
    let values = [
        &raw[7..11],
        &raw[0..2],
        &raw[12..14],
        &raw[15..17],
        &raw[18..20],
        &raw[22..24],
        &raw[24..26],
    ];
    let Some(values) = numbers(&values) else {
        return Err(Failure::Unsupported(
            "CLF timestamp requires Python strptime fallback".into(),
        ));
    };
    if values[6] > 59 {
        return Err(Failure::Unsupported(
            "CLF offset normalization requires Python fallback".into(),
        ));
    }
    let (year, day, hour, minute, second) = (values[0], values[1], values[2], values[3], values[4]);
    let offset = values[5] * 60 + values[6];
    if !valid_date(year, month, day, hour, minute, second) || offset >= 24 * 60 {
        return Ok(None);
    }
    let sign = if offset > 0 && bytes[21] == b'-' {
        '-'
    } else {
        '+'
    };
    Ok(Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{sign}{:02}:{:02}",
        offset / 60,
        offset % 60
    )))
}

fn iis_time(date: &str, time: &str) -> Result<Option<String>, Failure> {
    if !date.is_ascii()
        || !time.is_ascii()
        || date.len() != 10
        || time.len() != 8
        || date.as_bytes()[4] != b'-'
        || date.as_bytes()[7] != b'-'
        || time.as_bytes()[2] != b':'
        || time.as_bytes()[5] != b':'
    {
        return Err(Failure::Unsupported(
            "IIS timestamp requires Python strptime fallback".into(),
        ));
    }
    let Some(values) = numbers(&[
        &date[..4],
        &date[5..7],
        &date[8..],
        &time[..2],
        &time[3..5],
        &time[6..],
    ]) else {
        return Ok(None);
    };
    if !valid_date(
        values[0], values[1], values[2], values[3], values[4], values[5],
    ) {
        return Ok(None);
    }
    Ok(Some(format!("{date}T{time}")))
}

fn numbers<const N: usize>(values: &[&str; N]) -> Option<[u32; N]> {
    let mut parsed = [0; N];
    for (index, value) in values.iter().enumerate() {
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        parsed[index] = value.parse().ok()?;
    }
    Some(parsed)
}

fn valid_date(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> bool {
    if year == 0
        || year > 9999
        || !(1..=12).contains(&month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day > 0 && day <= days
}

// Python json.dumps' default ensure_ascii=True and separators=(", ", ": ").
fn json_ascii(value: &str) -> String {
    let mut result = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\u{8}' => result.push_str("\\b"),
            '\u{c}' => result.push_str("\\f"),
            c if c < ' ' || c > '\u{7e}' => {
                let number = c as u32;
                if number <= 0xffff {
                    result.push_str(&format!("\\u{number:04x}"));
                } else {
                    let adjusted = number - 0x10000;
                    result.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xd800 + (adjusted >> 10),
                        0xdc00 + (adjusted & 0x3ff)
                    ));
                }
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}
