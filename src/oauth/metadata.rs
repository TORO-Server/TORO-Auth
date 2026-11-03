//! 発見用のメタデータ

use axum::response::Response;
use serde_json::json;

use crate::App;
use crate::http::{self, Ctx};
use crate::site;

/// RFC 9728: Protected Resource Metadata
pub fn protected_resource(app: &App, ctx: &Ctx) -> Response {
    let mcp = &app.cfg.mcp_url;
    let data = json!({
        "resource": mcp,
        "resource_name": "TORO Server",
        "logo_uri": site::icon_data_uri(),
        "authorization_servers": [app.cfg.issuer],
        "scopes_supported": ["read", "write", "mcp"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": app.cfg.connect_page(),
    });
    http::pretty_json(http::cors_headers(ctx), &data, 200)
}

/// RFC 8414 / OpenID Connect: Authorization Server Metadata
pub fn authorization_server(app: &App, ctx: &Ctx) -> Response {
    let issuer = &app.cfg.issuer;
    let data = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "userinfo_endpoint": format!("{issuer}/oauth/userinfo"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "scopes_supported": ["read", "write", "mcp"],
        "service_documentation": app.cfg.connect_page(),
        "logo_uri": site::icon_data_uri(),
    });
    http::pretty_json(http::cors_headers(ctx), &data, 200)
}
