import { check } from "k6";
import crypto from "k6/crypto";
import http from "k6/http";
import encoding from "k6/encoding";
import exec from "k6/execution";
import {
    randomString,
    randomIntBetween,
} from "https://jslib.k6.io/k6-utils/1.3.0/index.js";
import { Counter } from "k6/metrics";

const payloadSize = __ENV.PAYLOAD_SIZE || 1024;
const validJWTRate = __ENV.AUTH || 1;
const data = randomString(payloadSize);

const backends = [
    new Counter("backend1"),
    new Counter("backend2"),
    new Counter("backend3"),
    new Counter("backend4"),
];
const authorized = new Counter("authorized");

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

function generateWebToken(id, valid) {
    const claim = {
        sub: id,
        name: "John Doe",
    };
    const secret = valid ? "testtest12345678" : "invalid";

    return encode(claim, secret);
}

export function randomRequest() {
    const server = __ENV.BACKEND || randomIntBetween(1, 4);
    var url = null;
    const direct = (__ENV.DIRECT || "0") == "1";
    if (direct) {
        const port = randomIntBetween(1, 4);
        url = `http://10.0.${server}.1:800${port}`;
    } else {
        url = `http://127.0.0.1:3000`;
    }

    requestTo(url, server);
}

export function requestTo(url, server) {
    const signature = `server${server}`;
    backends[server - 1].add(1);

    const isAuthorized = Math.random() < validJWTRate;
    if (isAuthorized) {
        authorized.add(1);
    }

    const id = exec.scenario.iterationInInstance.toString();
    const payload = data.substring(0, payloadSize - id.length) + id;
    const headers = {
        backend: signature,
        Authorization: "Bearer " + generateWebToken(id, isAuthorized),
    };
    const params = {
        headers: headers,
        timeout: "3s",
    };

    const res = http.post(url, payload, params);
    let passed = check(res, {
        "status is 200": (r) => r.status === 200,
        "processed by correct backend": (r) =>
            r.headers["Signature"] == signature,
        "body is the same": (r) => r.body === payload,
    });

    if (!passed && res.body != null) {
        console.log(
            `Failed request to ${url}: req = ${payload}, res = ${res.body}`,
        );
    }

    return passed;
}
