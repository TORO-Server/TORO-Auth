//! ChatGPT Actions / Gemini 向けの OpenAPI 仕様

use crate::http::{self, Ctx};
use crate::{App, template};
use axum::response::Response;

pub fn handle(app: &App, _ctx: &Ctx) -> Response {
    let spec = template::render(
        include_str!("../assets/openapi/openapi.json"),
        &[("SERVER_URL", &app.cfg.api_url)],
    );
    http::respond(
        200,
        http::public_headers(),
        http::JSON_UTF8,
        spec.trim_end().to_string(),
    )
}
