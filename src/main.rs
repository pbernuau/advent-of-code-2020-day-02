use core::fmt;
use std::cmp::Eq;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::path::Path;

use regex::Regex;

fn main() {
    let database: Vec<PasswordEntry> = read_lines("./input")
        .unwrap()
        .filter_map(|line| line.ok())
        .filter_map(|str| PasswordEntry::parse(str.as_str()))
        .collect();

    let total = database.len();
    let valid = database.iter()
        .filter(|e| e.is_valid(PasswordPolicyMode::TobogganCorporate))
        .count();
    let invalid = total - valid;

    println!("There are {} / {} valid passwords ({} invalid passwords)", valid, total, invalid);
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[derive(Debug, Eq, PartialEq)]
struct PasswordEntry {
    policy: PasswordPolicy,
    password: String,
}

impl PasswordEntry {
    fn new(policy: PasswordPolicy, password: &str) -> PasswordEntry {
        PasswordEntry {
            policy,
            password: String::from(password),
        }
    }

    fn parse(s: &str) -> Option<PasswordEntry> {
        let parts: Vec<&str> = s.splitn(2, ":").collect();
        let policy = parts.get(0).map(|s| s.trim()).and_then(PasswordPolicy::parse)?;
        let password = parts.get(1).map(|s| s.trim())?;

        Some(PasswordEntry::new(policy, password))
    }

    fn is_valid(&self, mode: PasswordPolicyMode) -> bool {
        self.policy.validate(mode, self.password.as_str())
    }
}

impl fmt::Display for PasswordEntry {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}: {}", self.policy, self.password)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PasswordPolicy {
    pattern: char,
    first: u32,
    second: u32,
}

enum PasswordPolicyMode {
    SledRental,
    TobogganCorporate,
}

impl PasswordPolicy {
    fn new(pattern: char, first: u32, second: u32) -> PasswordPolicy {
        PasswordPolicy {
            pattern,
            first,
            second,
        }
    }

    fn parse(s: &str) -> Option<PasswordPolicy> {
        let regex = Regex::new(r"^(\d{1,3})-(\d{1,3})\s([a-z])$").unwrap();
        let capture = regex.captures(s)?;

        let first = capture.get(1)?.as_str().parse().ok()?;
        let second = capture.get(2)?.as_str().parse().ok()?;
        let pattern = capture.get(3)?.as_str();

        Some(PasswordPolicy::new(pattern.chars().next()?, first, second))
    }

    fn validate(&self, mode: PasswordPolicyMode, s: &str) -> bool {
        match mode {
            PasswordPolicyMode::SledRental => {
                let count = s.matches(self.pattern).count() as u32;
                self.first <= count && count <= self.second
            }
            PasswordPolicyMode::TobogganCorporate => {
                let first_char = s.chars().nth((self.first - 1) as usize);
                let second_char = s.chars().nth((self.second - 1) as usize);

                first_char.map(|c| c == self.pattern) != second_char.map(|c| c == self.pattern)
            }
        }
    }
}

impl fmt::Display for PasswordPolicy {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}-{} {}", self.first, self.second, self.pattern)
    }
}

#[cfg(test)]
mod tests {
    use crate::PasswordPolicyMode::{SledRental, TobogganCorporate};

    use super::*;

    #[test]
    fn test_password_policy_to_string() {
        assert_eq!(PasswordPolicy::new('h', 9, 15).to_string(), "9-15 h");
    }

    #[test]
    fn test_password_policy_parse() {
        assert_eq!(PasswordPolicy::parse(""), None);
        assert_eq!(PasswordPolicy::parse("1- a"), None);
        assert_eq!(PasswordPolicy::parse("abc"), None);
        assert_eq!(PasswordPolicy::parse("1-3 a"), Some(PasswordPolicy::new('a', 1, 3)));
        assert_eq!(PasswordPolicy::parse("1-3 b"), Some(PasswordPolicy::new('b', 1, 3)));
        assert_eq!(PasswordPolicy::parse("2-9 c"), Some(PasswordPolicy::new('c', 2, 9)));
    }

    #[test]
    fn test_password_policy_validate() {
        assert_eq!(PasswordPolicy::parse("1-3 a").unwrap().validate(SledRental, "abcde"), true);
        assert_eq!(PasswordPolicy::parse("1-3 b").unwrap().validate(SledRental, "cdefg"), false);
        assert_eq!(PasswordPolicy::parse("2-9 c").unwrap().validate(SledRental, "ccccccccc"), true);

        assert_eq!(PasswordPolicy::parse("1-3 a").unwrap().validate(TobogganCorporate, "abcde"), true);
        assert_eq!(PasswordPolicy::parse("1-3 b").unwrap().validate(TobogganCorporate, "cdefg"), false);
        assert_eq!(PasswordPolicy::parse("2-9 c").unwrap().validate(TobogganCorporate, "ccccccccc"), false);
    }
}
