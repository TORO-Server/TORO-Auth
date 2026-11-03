//! HTML の小さなテンプレート。`{{KEY}}` を置き換える

pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            // 値の中の {{KEY}} が、あとの置き換えで展開されないように
            '{' => out.push_str("&#123;"),
            _ => out.push(c),
        }
    }
    out
}

/// 画面の `{{V}}` に入れて、新しい版を出すたびにアセットの URL を変える (Cloudflare のキャッシュを確実に切り替える)
pub fn with_asset_version(html: &str) -> String {
    html.replace("{{V}}", env!("CARGO_PKG_VERSION"))
}

/// 値はすべてエスケープして埋め込む
pub fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        out = out.replace(&format!("{{{{{key}}}}}"), &escape(value));
    }
    out
}

/// 組み立て済みの HTML の断片を埋め込む (エスケープしない)
pub fn insert_block(template: &str, key: &str, block: &str) -> String {
    template.replace(&format!("{{{{{key}}}}}"), block)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_escapes_values() {
        assert_eq!(
            render("<p>{{A}}</p>", &[("A", "<script>&\"'")]),
            "<p>&lt;script&gt;&amp;&quot;&#39;</p>"
        );
    }

    #[test]
    fn insert_block_keeps_html() {
        assert_eq!(
            insert_block("<div>{{B}}</div>", "B", "<b>x</b>"),
            "<div><b>x</b></div>"
        );
    }
}
