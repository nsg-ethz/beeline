import { check } from "k6";
import http from "k6/http";
import exec from "k6/execution";
import { randomString, randomIntBetween } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";
import { Counter } from "k6/metrics";

const payloadSize = __ENV.PAYLOAD_SIZE || 1024;
const data = randomString(payloadSize);

const backends = [
  new Counter("backend1"),
  new Counter("backend2"),
  new Counter("backend3"),
  new Counter("backend4")
];

export function randomRequest() {
  const server = __ENV.BACKEND || randomIntBetween(1, 4);
  requestTo(server);
}

export function requestTo(server) {
  const signature = `server${server}`;

  var url = null;
  const direct = (__ENV.DIRECT || "0") == "1";
  if (direct) {
    url = `http://10.0.${server}.1:8000`;
  }
  else {
    url = `http://127.0.0.1:3000`;
  }

  backends[server-1].add(1);

  const id = exec.scenario.iterationInInstance.toString();
  const payload = data.substring(0, payloadSize-id.length) + id;
  const headers = {
    "backend": signature,
    "conn-id": exec.vu.idInTest
  };

  const res = http.post(url, payload, { headers: headers });
  let passed = check(res, {
    "status is 200": (r) => r.status === 200,
    "processed by correct backend": (r) => r.headers["Signature"] == signature,
    // "benchmark is performance": (r) => r.headers["Benchmark"] === "performance",
    "body is the same": (r) => r.body === payload,
  });

  let abortOnFail = __ENV.ABORT_ON_FAIL || "0";
  abortOnFail = ["1", "true"].includes(abortOnFail.toLowerCase());
  if (!passed && abortOnFail) {
    exec.test.abort();
  }
}
