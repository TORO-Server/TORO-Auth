//! Minecraft サーバーの稼働状態。外部のサービスを使わず、Server List Ping で直接尋ねる

use std::io;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Default)]
pub struct Status {
    pub version: String,
    pub online: i64,
    pub max: i64,
    pub players: Vec<String>,
    pub motd: Vec<String>,
}

pub async fn ping(addr: &str, hostname: &str) -> io::Result<Status> {
    match tokio::time::timeout(TIMEOUT, ping_inner(addr, hostname)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "status ping timed out",
        )),
    }
}

async fn ping_inner(addr: &str, hostname: &str) -> io::Result<Status> {
    let mut stream = TcpStream::connect(addr).await?;
    let port = addr
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(25565);

    // Handshake (次の状態 = 1: Status) と Status Request
    let mut handshake = vec![0x00];
    write_varint(&mut handshake, -1);
    write_varint(&mut handshake, hostname.len() as i32);
    handshake.extend_from_slice(hostname.as_bytes());
    handshake.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut handshake, 1);

    let mut out = Vec::with_capacity(handshake.len() + 8);
    write_varint(&mut out, handshake.len() as i32);
    out.extend_from_slice(&handshake);
    out.extend_from_slice(&[0x01, 0x00]);
    stream.write_all(&out).await?;

    let length = read_varint(&mut stream).await? as usize;
    if length == 0 || length > MAX_RESPONSE_BYTES {
        return Err(invalid("bad packet length"));
    }
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await?;

    let mut cursor = packet.as_slice();
    if read_varint(&mut cursor).await? != 0 {
        return Err(invalid("unexpected packet id"));
    }
    let text_length = read_varint(&mut cursor).await? as usize;
    let text = cursor
        .get(..text_length)
        .ok_or_else(|| invalid("short status text"))?;
    let json: Value = serde_json::from_slice(text).map_err(|_| invalid("status is not JSON"))?;
    Ok(parse_status(&json))
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn write_varint(out: &mut Vec<u8>, value: i32) {
    let mut rest = value as u32;
    loop {
        let byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

async fn read_varint<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<i32> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = reader.read_u8().await?;
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value as i32);
        }
    }
    Err(invalid("varint too long"))
}

fn parse_status(json: &Value) -> Status {
    Status {
        version: json["version"]["name"].as_str().unwrap_or("").to_string(),
        online: json["players"]["online"].as_i64().unwrap_or(0),
        max: json["players"]["max"].as_i64().unwrap_or(0),
        players: json["players"]["sample"]
            .as_array()
            .map(|sample| {
                sample
                    .iter()
                    .filter(|p| is_real_player(p))
                    .filter_map(|p| p["name"].as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        motd: motd_lines(&json["description"]),
    }
}

/// サーバーは一覧に飾りの行 (`§b0/ 100` など) を混ぜることがある。id が 0 だけのものと、色の指定を含むものは人ではない
fn is_real_player(sample: &Value) -> bool {
    let name = sample["name"].as_str().unwrap_or("");
    let id = sample["id"].as_str().unwrap_or("");
    !name.is_empty() && !name.contains('§') && id.chars().any(|c| c != '0' && c != '-')
}

/// MOTD (文字列またはチャットコンポーネント) を、色の指定を除いた行にする
fn motd_lines(description: &Value) -> Vec<String> {
    let mut text = String::new();
    flatten_chat(description, &mut text);
    strip_formatting(&text)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn flatten_chat(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => out.push_str(text),
        Value::Array(items) => items.iter().for_each(|item| flatten_chat(item, out)),
        Value::Object(object) => {
            if let Some(text) = object.get("text") {
                flatten_chat(text, out);
            }
            if let Some(extra) = object.get("extra") {
                flatten_chat(extra, out);
            }
        }
        _ => {}
    }
}

fn strip_formatting(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '§' {
            chars.next();
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_status_json() {
        let status = parse_status(&json!({
            "version": { "name": "Velocity 26.3", "protocol": 775 },
            "players": { "online": 2, "max": 100, "sample": [
                { "name": "a", "id": "069a79f4-44e9-4726-a5be-fca90e38aaf5" },
                { "name": "b", "id": "61699b2e-d327-4a01-9f1e-0ea8c3f06bc6" },
                { "name": "§b0/ 100", "id": "61699b2e-d327-4a01-9f1e-0ea8c3f06bc7" },
                { "name": "decoration", "id": "00000000-0000-0000-0000-000000000000" },
            ] },
            "description": { "text": "§aTORO ", "extra": [{ "text": "Server\n" }, { "text": "§l二行目" }] },
        }));
        assert_eq!(status.version, "Velocity 26.3");
        assert_eq!((status.online, status.max), (2, 100));
        assert_eq!(status.players, ["a", "b"]);
        assert_eq!(status.motd, ["TORO Server", "二行目"]);
    }

    #[test]
    fn plain_string_motd() {
        assert_eq!(motd_lines(&json!("§cHello")), ["Hello"]);
    }

    #[tokio::test]
    async fn pings_a_server_over_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let handshake_length = read_varint(&mut stream).await.unwrap() as usize;
            let mut handshake = vec![0u8; handshake_length];
            stream.read_exact(&mut handshake).await.unwrap();
            assert_eq!(handshake[0], 0x00);
            assert!(handshake.windows(12).any(|w| w == b"torosaba.net"));
            let mut request = [0u8; 2];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x01, 0x00]);

            let text =
                r#"{"version":{"name":"Test"},"players":{"online":1,"max":5},"description":"hi"}"#;
            let mut body = vec![0x00];
            write_varint(&mut body, text.len() as i32);
            body.extend_from_slice(text.as_bytes());
            let mut packet = Vec::new();
            write_varint(&mut packet, body.len() as i32);
            packet.extend_from_slice(&body);
            stream.write_all(&packet).await.unwrap();
        });

        let status = ping(&addr, "torosaba.net").await.unwrap();
        server.await.unwrap();
        assert_eq!(status.version, "Test");
        assert_eq!((status.online, status.max), (1, 5));
    }

    #[tokio::test]
    async fn unreachable_server_is_an_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        assert!(ping(&addr, "torosaba.net").await.is_err());
    }
}
