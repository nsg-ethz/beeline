import { check } from "k6";
import crypto from "k6/crypto";
import http from "k6/http";
import encoding from "k6/encoding";
import exec from "k6/execution";
import { randomString } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

export const url = __ENV.URL || "http://127.0.0.1:9999";
export const payloadSize = __ENV.PAYLOAD_SIZE || 1024;
export const randomData = randomString(payloadSize);

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

export function generateWebToken(valid) {
    const claim = {
        sub: exec.scenario.iterationInInstance.toString(),
        name: "John Doe",
    };
    const secret = valid ? "testtest12345678" : "invalid";

    return encode(claim, secret);
}

export function request() {
    requestTo(url);
}

export function requestTo(url, headers = {}) {
    const id = exec.scenario.iterationInInstance.toString();
    const payload = randomData.substring(0, payloadSize - id.length) + id;

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
