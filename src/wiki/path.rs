//! 原稿のパス。どの入口から来ても docs/ の下の .md だけを指すようにする

/// `07_System/a` → `docs/07_System/a.md`。docs/ の外に出るものなどは None
pub fn normalize(path: &str) -> Option<String> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.contains('\\') || trimmed.chars().any(char::is_control) {
        return None;
    }
    if trimmed
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    let mut clean = if trimmed.starts_with("docs/") {
        trimmed.to_string()
    } else {
        format!("docs/{trimmed}")
    };
    if !clean.ends_with(".md") {
        clean.push_str(".md");
    }
    Some(clean)
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn adds_prefix_and_suffix() {
        assert_eq!(
            normalize("07_System/a").as_deref(),
            Some("docs/07_System/a.md")
        );
        assert_eq!(
            normalize("/docs/日本語.md").as_deref(),
            Some("docs/日本語.md")
        );
    }

    #[test]
    fn rejects_paths_leaving_docs() {
        for bad in [
            "",
            "../secret",
            "a/../../b",
            "a/./b",
            "a//b",
            "a\\b",
            "a\nb",
            "docs/../.github/x",
        ] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
    }
}
