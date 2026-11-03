//! OAuth の HTML 画面

use crate::auth::session::Session;
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

pub fn consent(options: &Consent) -> String {
    let section = match (options.session, options.approve_url) {
        (Some(session), Some(approve_url)) => {
            let (color, label) = if session.can_edit() {
                ("#00ff00", "[TORO MEMBER] (WIKI WRITE ENABLED)")
            } else {
                ("#ffff00", "[GUEST] (READ ONLY)")
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
    insert_block(&page, "USER_SECTION", &section)
}

pub fn denied(client_name: &str, client_redirect: Option<&str>, retry_url: &str) -> String {
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
    insert_block(&page, "CLIENT_RETURN", &client_return)
}

pub fn invalid_request(message: &str) -> String {
    render(
        include_str!("../../assets/oauth/error.html"),
        &[("MESSAGE", message)],
    )
}
