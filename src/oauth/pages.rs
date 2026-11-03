//! OAuth の HTML 画面

use crate::auth::session::{Session, scope_allows_write};
use crate::config::Config;
use crate::template::{insert_block, render};

pub struct Consent<'a> {
    pub client_name: &'a str,
    pub redirect_target: &'a str,
    pub scope: &'a str,
    pub session: Option<&'a Session>,
    pub login_url: &'a str,
    /// ログイン済みのときだけある
    pub approve_url: Option<&'a str>,
    pub deny_url: &'a str,
}

const WRITE_PERMISSION: &str = "<li>+ Wiki の編集と保存 (GitHub へのコミット。メンバーのみ)</li>";
const NO_WRITE_PERMISSION: &str = "<li>- Wiki の編集は求めていません (読むだけ)</li>";

pub fn consent(cfg: &Config, options: &Consent) -> String {
    let write_requested = scope_allows_write(options.scope);
    let section = match (options.session, options.approve_url) {
        (Some(session), Some(approve_url)) => {
            let (color, label) = if !session.can_edit() {
                ("#ffe070", "ゲスト (読むだけ)")
            } else if write_requested {
                ("#7cf0b0", "TORO メンバー (Wiki の編集ができます)")
            } else {
                (
                    "#7cf0b0",
                    "TORO メンバー (このクライアントには読むだけを許可)",
                )
            };
            render(
                include_str!("../../assets/oauth/consent_session.html"),
                &[
                    ("USERNAME", session.username()),
                    ("ROLE_COLOR", color),
                    ("ROLE_LABEL", label),
                    ("APPROVE_URL", approve_url),
                    ("DENY_URL", options.deny_url),
                ],
            )
        }
        _ => render(
            include_str!("../../assets/oauth/consent_guest.html"),
            &[
                ("LOGIN_URL", options.login_url),
                ("DENY_URL", options.deny_url),
            ],
        ),
    };
    let page = render(
        include_str!("../../assets/oauth/consent.html"),
        &[
            ("CLIENT_NAME", options.client_name),
            ("REDIRECT_TARGET", options.redirect_target),
            ("SCOPE", options.scope),
        ],
    );
    let page = insert_block(
        &page,
        "WRITE_PERMISSION",
        if write_requested {
            WRITE_PERMISSION
        } else {
            NO_WRITE_PERMISSION
        },
    );
    cfg.fill_links(&insert_block(&page, "USER_SECTION", &section))
}

pub fn denied(
    cfg: &Config,
    client_name: &str,
    client_redirect: Option<&str>,
    retry_url: &str,
) -> String {
    let client_return = client_redirect.map_or_else(String::new, |url| {
        render(
            include_str!("../../assets/oauth/denied_return.html"),
            &[("CLIENT_REDIRECT", url)],
        )
    });
    let page = render(
        include_str!("../../assets/oauth/denied.html"),
        &[("CLIENT_NAME", client_name), ("RETRY_URL", retry_url)],
    );
    cfg.fill_links(&insert_block(&page, "CLIENT_RETURN", &client_return))
}

pub fn invalid_request(cfg: &Config, message: &str) -> String {
    let page = render(
        include_str!("../../assets/oauth/error.html"),
        &[("MESSAGE", message)],
    );
    cfg.fill_links(&page)
}
