import { check } from "k6";
import crypto from "k6/crypto";
import http from "k6/http";
import encoding from "k6/encoding";
import exec from "k6/execution";

export const url = __ENV.URL || "http://127.0.0.1:8080";

export const payloadSize = __ENV.PAYLOAD_SIZE || 1024;
const randomBody = "b".repeat(payloadSize);

export const headers = new Object();
(__ENV.HEADERS == null ? "" : __ENV.HEADERS).split(",").forEach((header) => {
    const [key, val] = header.split(":");
    headers[key.trim()] = val.trim();
});

function sign(data, hashAlg, secret) {
    let hasher = crypto.createHMAC(hashAlg, secret);
    hasher.update(data);

    // Some manual base64 rawurl encoding as `Hasher.digest(encodingType)`
    // doesn't support that encoding type yet.
    return hasher
        .digest("base64")
        .replace(/\//g, "_")
        .replace(/\+/g, "-")
        .replace(/=/g, "");
}

function encode(payload, secret, algorithm) {
    const algoToHash = {
        HS256: "sha256",
        HS384: "sha384",
        HS512: "sha512",
    };

    algorithm = algorithm || "HS256";
    let header = encoding.b64encode(
        JSON.stringify({ typ: "JWT", alg: algorithm }),
        "rawurl",
    );
    payload = encoding.b64encode(JSON.stringify(payload), "rawurl");
    let sig = sign(header + "." + payload, algoToHash[algorithm], secret);
    return [header, payload, sig].join(".");
}

export function generateWebToken(valid, claims = {}) {
    const payload = claims
        ? claims
        : {
              sub: exec.scenario.iterationInInstance.toString(),
              name: "John Doe",
          };
    const secret = valid ? "testtest12345678" : "invalid";

    return encode(payload, secret);
}

export function request() {
    requestTo(url, headers);
}

export function requestTo(url, headers = {}) {
    const id = exec.scenario.iterationInInstance.toString();
    const payload = randomBody.substring(0, payloadSize - id.length) + id;

    const params = {
        headers: headers,
        timeout: "3s",
    };

    const res = http.post(url, payload, params);
    let passed = check(res, {
        "status is 200": (r) => r.status === 200,
        "body is the same": (r) => r.body === payload,
    });

    if (!passed && res.body != null) {
        console.log(
            `Failed request to ${url}:\nreq = ${payload},\nres = ${res.body},\nheaders = ${JSON.stringify(res.headers)}`,
        );
    }

    return passed;
}
