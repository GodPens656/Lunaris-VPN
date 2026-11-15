use crate::models::{Profile, Settings};
use blake2::{digest::consts::U32, Blake2b, Digest};
use rand::RngCore;
use ring::{aead, hmac};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Latency {
    pub label: String,
    pub milliseconds: Option<f64>,
    pub error: Option<String>,
}
impl Latency {
    pub fn ok(ms: f64) -> Self {
        Self {
            label: format!("{ms:.1} мс"),
            milliseconds: Some(ms),
            error: None,
        }
    }
    pub fn error(s: &str) -> Self {
        Self {
            label: s.into(),
            milliseconds: None,
            error: Some(s.into()),
        }
    }
}
pub async fn measure(p: &Profile, s: &Settings, method: &str, connected: bool) -> Latency {
    let host = p.outbound["server"].as_str().unwrap_or("");
    let port = p.outbound["server_port"].as_u64().unwrap_or(0) as u16;
    let start = Instant::now();
    match method {
        "tcp" if p.protocol() == "hysteria2" => {
            match tokio::time::timeout(
                Duration::from_secs(5),
                udp(host, port, p.outbound["obfs"]["password"].as_str()),
            )
            .await
            {
                Ok(Ok(())) => Latency::ok(start.elapsed().as_secs_f64() * 1000.),
                Ok(Err(_)) => Latency::error("UDP-порт недоступен"),
                Err(_) => Latency::error("Тайм-аут UDP"),
            }
        }
        "tcp" => {
            match tokio::time::timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
                .await
            {
                Ok(Ok(_)) => Latency::ok(start.elapsed().as_secs_f64() * 1000.),
                Ok(Err(_)) => Latency::error("TCP-порт недоступен"),
                Err(_) => Latency::error("Тайм-аут TCP"),
            }
        }
        "icmp" => icmp(host).await,
        "proxy" if connected => proxy(s).await,
        "proxy" => Latency::error("Подключите VPN"),
        _ => Latency::error("Неизвестный метод измерения"),
    }
}
pub async fn proxy(s: &Settings) -> Latency {
    let result = async {
        let proxy =
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", s.mixed_port)).map_err(|_| ())?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(proxy)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| ())?;
        let start = Instant::now();
        let response = client.get(&s.probe_url).send().await.map_err(|_| ())?;
        Ok::<_, ()>(if response.status().is_success() {
            Latency::ok(start.elapsed().as_secs_f64() * 1000.)
        } else {
            Latency::error(&format!("HTTP {}", response.status().as_u16()))
        })
    }
    .await;
    result.unwrap_or_else(|_| Latency::error("GET через прокси не выполнен"))
}
async fn icmp(host: &str) -> Latency {
    let mut cmd = tokio::process::Command::new("ping");
    #[cfg(windows)]
    {
        cmd.args(["-n", "1", "-w", "4000"]);
        cmd.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    cmd.args(["-n", "-c", "1"]);
    cmd.arg(host).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(5), cmd.output()).await;
    if let Ok(Ok(o)) = output {
        if o.status.success() {
            // The numeric portion and ASCII '='/'<' survive Windows OEM encodings.
            let text = String::from_utf8_lossy(&o.stdout);
            let re =
                regex::Regex::new(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс|[^\x00-\x7F]+)").unwrap();
            if let Some(c) = re.captures(&text) {
                if let Ok(ms) = c[1].replace(',', ".").parse::<f64>() {
                    let mut r = Latency::ok(ms);
                    if c[0].starts_with('<') {
                        r.label = format!("<{ms:.1} мс");
                    }
                    return r;
                }
            }
        }
    }
    Latency::error("Нет ответа ICMP")
}
fn expand(secret: &[u8], label: &[u8], size: usize) -> Vec<u8> {
    let label = [b"tls13 ".as_slice(), label].concat();
    let mut info = (size as u16).to_be_bytes().to_vec();
    info.push(label.len() as u8);
    info.extend(label);
    info.extend([0, 1]);
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), &info).as_ref()[..size].to_vec()
}
fn keys(destination: &[u8], side: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let salt = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let initial = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &salt), destination);
    let label = [side, b" in"].concat();
    let secret = expand(initial.as_ref(), &label, 32);
    (
        expand(&secret, b"quic key", 16),
        expand(&secret, b"quic iv", 12),
        expand(&secret, b"quic hp", 16),
    )
}
fn mask(key: &[u8], sample: &[u8]) -> Option<[u8; 5]> {
    aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, key)
        .ok()?
        .new_mask(sample)
        .ok()
}
fn cipher(key: &[u8]) -> Option<aead::LessSafeKey> {
    Some(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, key).ok()?,
    ))
}
fn varint(value: usize) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else {
        ((value as u16) | 0x4000).to_be_bytes().to_vec()
    }
}
fn read_varint(data: &[u8], offset: &mut usize) -> Option<usize> {
    let size = 1usize << (*data.get(*offset)? >> 6);
    let bytes = data.get(*offset..*offset + size)?;
    *offset += size;
    let mut value = 0usize;
    for b in bytes {
        value = (value << 8) | *b as usize;
    }
    Some(value & ((1usize << (size * 8 - 2)) - 1))
}
pub fn initial(destination: &[u8], source: &[u8]) -> Option<Vec<u8>> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .ok()?
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let params = [&[0x0f, source.len() as u8], source].concat();
    let mut conn = rustls::quic::ClientConnection::new(
        Arc::new(tls),
        rustls::quic::Version::V1,
        "localhost".try_into().ok()?,
        params,
    )
    .ok()?;
    let mut hello = Vec::new();
    conn.write_hs(&mut hello);
    let mut frames = vec![0x06, 0];
    frames.extend(varint(hello.len()));
    frames.extend(hello);
    let mut prefix = vec![0xc3, 0, 0, 0, 1, destination.len() as u8];
    prefix.extend(destination);
    prefix.push(source.len() as u8);
    prefix.extend(source);
    prefix.push(0);
    let payload_size = 1200usize.checked_sub(prefix.len() + 2 + 4 + 16)?;
    if frames.len() > payload_size {
        return None;
    }
    frames.resize(payload_size, 0);
    let mut header = prefix;
    header.extend(varint(4 + frames.len() + 16));
    header.extend([0; 4]);
    let (key, iv, hp) = keys(destination, b"client");
    cipher(&key)?
        .seal_in_place_append_tag(
            aead::Nonce::try_assume_unique_for_key(&iv).ok()?,
            aead::Aad::from(&header),
            &mut frames,
        )
        .ok()?;
    let mask = mask(&hp, frames.get(..16)?)?;
    header[0] ^= mask[0] & 0x0f;
    let len = header.len();
    for i in 0..4 {
        header[len - 4 + i] ^= mask[1 + i];
    }
    header.extend(frames);
    Some(header)
}
pub fn is_reply(data: &[u8], destination: &[u8], source: &[u8]) -> bool {
    let check = || -> Option<()> {
        if data.len() < 7 || data[0] & 0xc0 != 0xc0 || data.get(1..5)? != [0, 0, 0, 1] {
            return None;
        }
        let len = data[5] as usize;
        if data.get(6..6 + len)? != source {
            return None;
        }
        let mut offset = 6 + len;
        let len = *data.get(offset)? as usize;
        if len > 20 {
            return None;
        }
        offset += 1 + len;
        if data[0] & 0x30 == 0x30 {
            if data.len() <= offset + 16 {
                return None;
            }
            let pseudo = [
                &[destination.len() as u8],
                destination,
                data.get(..data.len() - 16)?,
            ]
            .concat();
            let mut tag = data.get(data.len() - 16..)?.to_vec();
            let key = [
                0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
                0xc8, 0x4e,
            ];
            cipher(&key)?
                .open_in_place(
                    aead::Nonce::assume_unique_for_key([
                        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
                    ]),
                    aead::Aad::from(pseudo),
                    &mut tag,
                )
                .ok()?;
            return Some(());
        }
        if data[0] & 0x30 != 0 {
            return None;
        }
        let token = read_varint(data, &mut offset)?;
        offset = offset.checked_add(token)?;
        let length = read_varint(data, &mut offset)?;
        let end = offset.checked_add(length)?;
        if end > data.len() || length < 20 {
            return None;
        }
        let (key, mut iv, hp) = keys(destination, b"server");
        let mask = mask(&hp, data.get(offset + 4..offset + 20)?)?;
        let first = data[0] ^ (mask[0] & 0x0f);
        let pnlen = (first & 3) as usize + 1;
        let mut header = data.get(..offset + pnlen)?.to_vec();
        header[0] = first;
        let mut number = 0u64;
        for i in 0..pnlen {
            header[offset + i] ^= mask[i + 1];
            number = (number << 8) | header[offset + i] as u64;
        }
        for (i, b) in number.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= *b;
        }
        let mut payload = data.get(offset + pnlen..end)?.to_vec();
        cipher(&key)?
            .open_in_place(
                aead::Nonce::try_assume_unique_for_key(&iv).ok()?,
                aead::Aad::from(header),
                &mut payload,
            )
            .ok()?;
        Some(())
    };
    check().is_some()
}
pub fn salamander(data: &[u8], password: &str, salt: &[u8]) -> Vec<u8> {
    let mut h = Blake2b::<U32>::new();
    h.update(password.as_bytes());
    h.update(salt);
    let mask = h.finalize();
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ mask[i % 32])
        .collect()
}
async fn udp(host: &str, port: u16, password: Option<&str>) -> std::io::Result<()> {
    let addr = tokio::net::lookup_host((host, port))
        .await?
        .next()
        .ok_or(std::io::ErrorKind::AddrNotAvailable)?;
    let socket = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(addr).await?;
    let mut dst = [0; 8];
    let mut src = [0; 8];
    rand::thread_rng().fill_bytes(&mut dst);
    rand::thread_rng().fill_bytes(&mut src);
    let mut packet = initial(&dst, &src).ok_or(std::io::ErrorKind::InvalidData)?;
    if let Some(password) = password {
        let mut salt = [0; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        packet = [salt.to_vec(), salamander(&packet, password, &salt)].concat();
    }
    socket.send(&packet).await?;
    let mut buffer = [0u8; 65536];
    loop {
        let n = socket.recv(&mut buffer).await?;
        let data = if let Some(p) = password {
            if n < 8 {
                continue;
            }
            salamander(&buffer[8..n], p, &buffer[..8])
        } else {
            buffer[..n].to_vec()
        };
        if is_reply(&data, &dst, &src) {
            return Ok(());
        }
    }
}
