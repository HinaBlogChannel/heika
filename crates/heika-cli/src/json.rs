//! JSON を書く。heika が出す JSON は小さく形も決まっているので、依存を足さずに組む。

use std::fmt::Write;

/// JSON の値。heika が書くものに要る種類だけを持つ。
#[derive(Debug, PartialEq, Eq)]
pub enum Value {
    /// JavaScript で丸められないように、2^53 より小さいものだけに使う
    Number(u64),
    Text(String),
    Array(Vec<Value>),
    /// キーは書いた順に並べる
    Object(Vec<(&'static str, Value)>),
}

impl Value {
    /// 2つの空白で字下げし、最後に改行を付ける
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.render_into(&mut out, 0);
        out.push('\n');
        out
    }

    fn render_into(&self, out: &mut String, depth: usize) {
        let indent = |out: &mut String, depth: usize| out.push_str(&"  ".repeat(depth));
        match self {
            Self::Number(number) => {
                write!(out, "{number}").expect("writing to a String never fails")
            }
            Self::Text(text) => out.push_str(&string(text)),
            Self::Array(items) if items.is_empty() => out.push_str("[]"),
            Self::Object(entries) if entries.is_empty() => out.push_str("{}"),
            Self::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    out.push_str(if i == 0 { "\n" } else { ",\n" });
                    indent(out, depth + 1);
                    item.render_into(out, depth + 1);
                }
                out.push('\n');
                indent(out, depth);
                out.push(']');
            }
            Self::Object(entries) => {
                out.push('{');
                for (i, (key, value)) in entries.iter().enumerate() {
                    out.push_str(if i == 0 { "\n" } else { ",\n" });
                    indent(out, depth + 1);
                    out.push_str(&string(key));
                    out.push_str(": ");
                    value.render_into(out, depth + 1);
                }
                out.push('\n');
                indent(out, depth);
                out.push('}');
            }
        }
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<u64> for Value {
    fn from(number: u64) -> Self {
        Self::Number(number)
    }
}

/// JSON の文字列。ノードが名乗った名前のように外から来た文字列も入るので、引用符と制御文字をエスケープする。
pub fn string(text: &str) -> String {
    let mut json = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => json.push_str("\\\""),
            '\\' => json.push_str("\\\\"),
            c if c.is_control() => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(json, "\\u{unit:04x}").expect("writing to a String never fails");
                }
            }
            c => json.push(c),
        }
    }
    json.push('"');
    json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_nested_values_that_a_json_parser_reads_back() {
        let value = Value::Object(vec![
            ("name", "a \"quoted\" \\ name\u{1}\n".into()),
            ("height", 5_855_996.into()),
            ("empty", Value::Array(Vec::new())),
            (
                "items",
                Value::Array(vec![Value::Object(vec![("x", 1.into())]), "日本語".into()]),
            ),
        ]);
        let rendered = value.render();
        assert_eq!(
            rendered,
            "{\n  \"name\": \"a \\\"quoted\\\" \\\\ name\\u0001\\u000a\",\n  \"height\": 5855996,\n  \"empty\": [],\n  \"items\": [\n    {\n      \"x\": 1\n    },\n    \"日本語\"\n  ]\n}\n"
        );
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["name"], "a \"quoted\" \\ name\u{1}\n");
        assert_eq!(parsed["height"], 5_855_996);
        assert_eq!(parsed["items"][0]["x"], 1);
        assert_eq!(parsed["items"][1], "日本語");
    }
}
