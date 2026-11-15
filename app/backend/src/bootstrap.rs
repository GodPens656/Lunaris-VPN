//! Resolve the VPN endpoint against the configured bootstrap IP before TUN.
use crate::Result;
use rand::Rng;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
fn name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    for _ in 0..128 {
        let n = *data.get(pos)? as usize;
        pos += 1;
        if n == 0 {
            if !jumped {
                *offset = pos;
            }
            return Some(labels.join(".").to_lowercase());
        }
        if n & 0xc0 == 0xc0 {
            let low = *data.get(pos)? as usize;
            if !jumped {
                *offset = pos + 1;
            }
            pos = ((n & 0x3f) << 8) | low;
            jumped = true;
            continue;
        }
        if n > 63 {
            return None;
        }
        let label = std::str::from_utf8(data.get(pos..pos + n)?).ok()?;
        labels.push(label.to_string());
        pos += n;
        if !jumped {
            *offset = pos;
        }
    }
    None
}
fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
pub fn parse_response(data: &[u8], id: u16, hostname: &str, kind: u16) -> Option<Vec<IpAddr>> {
    if u16_at(data, 0)? != id || u16_at(data, 2)? & 0x820f != 0x8000 || u16_at(data, 4)? != 1 {
        return None;
    }
    let mut offset = 12;
    if name(data, &mut offset)? != hostname.trim_end_matches('.').to_lowercase()
        || u16_at(data, offset)? != kind
        || u16_at(data, offset + 2)? != 1
    {
        return None;
    }
    offset += 4;
    let mut ips = BTreeMap::<String, Vec<IpAddr>>::new();
    let mut aliases = BTreeMap::new();
    for _ in 0..u16_at(data, 6)? {
        let owner = name(data, &mut offset)?;
        let typ = u16_at(data, offset)?;
        let class = u16_at(data, offset + 2)?;
        let len = u16_at(data, offset + 8)? as usize;
        offset += 10;
        let bytes = data.get(offset..offset + len)?;
        if class == 1 {
            match (typ, len) {
                (1, 4) => ips
                    .entry(owner)
                    .or_default()
                    .push(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?).into()),
                (28, 16) => ips
                    .entry(owner)
                    .or_default()
                    .push(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).into()),
                (5, _) => {
                    let mut pos = offset;
                    aliases.insert(owner, name(data, &mut pos)?);
                }
                _ => {}
            }
        }
        offset += len;
    }
    let mut host = hostname.trim_end_matches('.').to_lowercase();
    for _ in 0..32 {
        if let Some(addresses) = ips.remove(&host) {
            return Some(addresses);
        }
        host = aliases.remove(&host)?;
    }
    None
}
async fn query(host: &str, server: IpAddr, kind: u16) -> Result<Vec<IpAddr>> {
    let id = rand::thread_rng().gen::<u16>();
    let mut packet = Vec::new();
    packet.extend(id.to_be_bytes());
    packet.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Некорректный адрес VPN-сервера.".into());
        }
        packet.push(label.len() as u8);
        packet.extend(label.as_bytes());
    }
    packet.push(0);
    packet.extend(kind.to_be_bytes());
    packet.extend([0, 1]);
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(|_| "Bootstrap DNS недоступен.")?;
    socket
        .connect((server, 53))
        .await
        .map_err(|_| "Bootstrap DNS недоступен.")?;
    socket
        .send(&packet)
        .await
        .map_err(|_| "Bootstrap DNS недоступен.")?;
    let mut buffer = vec![0; 65535];
    let n = socket
        .recv(&mut buffer)
        .await
        .map_err(|_| "Bootstrap DNS не ответил.")?;
    buffer.truncate(n);
    if u16_at(&buffer, 0) == Some(id) && u16_at(&buffer, 2).is_some_and(|f| f & 0x200 != 0) {
        let mut stream = TcpStream::connect((server, 53))
            .await
            .map_err(|_| "Bootstrap TCP DNS недоступен.")?;
        stream
            .write_u16(packet.len() as u16)
            .await
            .map_err(|_| "Ошибка Bootstrap DNS.")?;
        stream
            .write_all(&packet)
            .await
            .map_err(|_| "Ошибка Bootstrap DNS.")?;
        let n = stream
            .read_u16()
            .await
            .map_err(|_| "Ошибка Bootstrap DNS.")?;
        buffer.resize(n as usize, 0);
        stream
            .read_exact(&mut buffer)
            .await
            .map_err(|_| "Ошибка Bootstrap DNS.")?;
    }
    Ok(parse_response(&buffer, id, host, kind).unwrap_or_default())
}
pub async fn resolve(host: &str, server: &str, ipv6: bool) -> Result<Vec<String>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip.to_string()]);
    }
    let server = server
        .parse()
        .map_err(|_| "Для Bootstrap DNS нужен IP-адрес.")?;
    let operation = async {
        let v4 = tokio::time::timeout(Duration::from_secs(5), query(host, server, 1));
        let v6 = async {
            if ipv6 {
                tokio::time::timeout(Duration::from_secs(5), query(host, server, 28))
                    .await
                    .ok()
                    .and_then(|v| v.ok())
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        };
        let (v4, v6) = tokio::join!(v4, v6);
        let mut ips = v4.ok().and_then(|v| v.ok()).unwrap_or_default();
        ips.extend(v6);
        let mut seen = std::collections::HashSet::new();
        ips.retain(|ip| seen.insert(*ip));
        if ips.is_empty() {
            return Err(
                "Не удалось разрешить адрес VPN-сервера до запуска TUN. Проверьте Bootstrap DNS."
                    .into(),
            );
        }
        Ok(ips.into_iter().map(|ip| ip.to_string()).collect())
    };
    tokio::time::timeout(Duration::from_secs(12), operation)
        .await
        .map_err(|_| "Bootstrap DNS не ответил.")?
}
