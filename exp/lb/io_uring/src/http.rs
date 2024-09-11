use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum HTTP {
    GET(String),
    POST(String),
    PUT(String),
    DELETE(String),
}

impl HTTP {

    pub fn url(&self) -> &String {
        match self {
            HTTP::GET(url) => url,
            HTTP::POST(url) => url,
            HTTP::PUT(url) => url,
            HTTP::DELETE(url) => url,
        }
    }

}

pub fn parse_hdr(buf: &[u8]) -> Option<(HTTP, HashMap<String, String>, usize)> {
    let raw = String::from_utf8_lossy(buf);
    let hdr_len = raw.find("\r\n\r\n")?;
    let lines = raw[..hdr_len].split("\r\n");

    let req_line = lines.clone()
        .filter(|line| line.starts_with("GET") || line.starts_with("POST") || line.starts_with("PUT") || line.starts_with("DELETE"))
        .next()?;

    let method = req_line.split_whitespace().next()?;
    let method = match method {
        "GET" => HTTP::GET(req_line.split_whitespace().nth(1)?.to_string()),
        "POST" => HTTP::POST(req_line.split_whitespace().nth(1)?.to_string()),
        "PUT" => HTTP::PUT(req_line.split_whitespace().nth(1)?.to_string()),
        "DELETE" => HTTP::DELETE(req_line.split_whitespace().nth(1)?.to_string()),
        _ => return None,
    };

    let hdr = lines
        .filter_map(|line| {
            let mut iter = line.splitn(2, ":");
            let key = iter.next()?.trim().to_lowercase();
            let val = iter.next()?.trim().to_lowercase();
            Some((key, val))
        })
        .collect();

    Some((method, hdr, hdr_len + 4)) 
}
