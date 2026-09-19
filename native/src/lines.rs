//! Bounded UTF-8 physical lines with Python str.splitlines semantics.
use std::fs::File;
use std::io::Read;

use crate::Failure;

pub struct Lines {
    file: File,
    text: String,
    cursor: usize,
    carry: Vec<u8>,
    eof: bool,
    first: bool,
    skip_lf: bool,
    max_chars: usize,
    path: String,
}

impl Lines {
    pub fn new(file: File, path: String, max_chars: usize) -> Self {
        Self {
            file,
            text: String::new(),
            cursor: 0,
            carry: Vec::new(),
            eof: false,
            first: true,
            skip_lf: false,
            max_chars,
            path,
        }
    }

    fn refill(&mut self) -> Result<bool, Failure> {
        if self.eof {
            return Ok(false);
        }
        let mut bytes = std::mem::take(&mut self.carry);
        let offset = bytes.len();
        bytes.resize(offset + 65_536, 0);
        let count = self.file.read(&mut bytes[offset..]).map_err(Failure::Io)?;
        bytes.truncate(offset + count);
        self.eof = count == 0;
        let valid_len = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(error) if error.error_len().is_none() && !self.eof => error.valid_up_to(),
            Err(_) => {
                return Err(Failure::Parse(format!(
                    "invalid UTF-8 in prepared source: {}",
                    self.path
                )))
            }
        };
        self.carry = bytes.split_off(valid_len);
        self.text = String::from_utf8(bytes).expect("validated UTF-8");
        self.cursor = 0;
        if self.first && (!self.text.is_empty() || self.eof) {
            self.first = false;
            if self.text.starts_with('\u{feff}') {
                self.cursor = '\u{feff}'.len_utf8();
            }
        }
        Ok(self.cursor < self.text.len() || !self.eof)
    }

    pub fn next(&mut self) -> Result<Option<String>, Failure> {
        let mut line = String::new();
        let mut chars = 0;
        loop {
            if self.cursor == self.text.len() && !self.refill()? {
                return Ok(if line.is_empty() { None } else { Some(line) });
            }
            if self.skip_lf {
                self.skip_lf = false;
                if self.text[self.cursor..].starts_with('\n') {
                    self.cursor += 1;
                }
                if self.cursor == self.text.len() {
                    continue;
                }
            }
            let tail = &self.text[self.cursor..];
            let ending = tail.char_indices().find(|(_, c)| is_line_break(*c));
            let (part, end) = match ending {
                Some((index, character)) => (&tail[..index], Some(character)),
                None => (tail, None),
            };
            chars += if part.is_ascii() {
                part.len()
            } else {
                part.chars().count()
            };
            if chars > self.max_chars {
                return Err(Failure::Parse(format!(
                    "text line exceeds {} characters: {}",
                    self.max_chars, self.path
                )));
            }
            line.push_str(part);
            self.cursor += part.len();
            if let Some(character) = end {
                self.cursor += character.len_utf8();
                self.skip_lf = character == '\r';
                return Ok(Some(line));
            }
        }
    }
}

fn is_line_break(character: char) -> bool {
    matches!(
        character,
        '\n' | '\r'
            | '\u{b}'
            | '\u{c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

pub fn python_whitespace(character: char) -> bool {
    character.is_whitespace() || matches!(character, '\u{1c}'..='\u{1f}')
}
