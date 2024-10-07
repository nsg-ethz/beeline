import { check } from "k6";
import http from "k6/http";
import exec from "k6/execution";
import { randomString, randomIntBetween } from "https://jslib.k6.io/k6-utils/1.5.0/index.js";
import { Counter } from "k6/metrics";
import { Client, StatusOK } from "k6/net/grpc";

const direct = ["1", "true", "t", ""].includes(__ENV.DIRECT);
const local = ["1", "true", "t", ""].includes(__ENV.LOCAL);
const modeIsHTTP = (__ENV.MODE || "http").toLowerCase() == "http";

const payloadSize = __ENV.PAYLOAD_SIZE || 1024;
const data = randomString(payloadSize);

const backends = [
  new Counter("backend1"),
  new Counter("backend2"),
  new Counter("backend3"),
  new Counter("backend4")
];

let client = null;
if (!modeIsHTTP) {
  client = new Client();
  client.load(["../proto"], "echo.proto");
}

function getAddressFor(server) {
  if (direct) {
    const address = (local) ? "127.0.0.1" : `10.0.${server}.1`;
    const port = (modeIsHTTP) ? 8000 : 50051;

    return `${address}:${port}`;
  }

  const address = (local) ? "127.0.0.1" : "10.0.5.1";
  return `${address}:3000`
}

export function randomRequest() {
  const server = __ENV.BACKEND || randomIntBetween(1, 4);
  requestTo(server);
}

export function requestTo(server) {
  backends[server-1].add(1);

  const addr = getAddressFor(server);
  const id = exec.scenario.iterationInInstance.toString();
  const payload = data.substring(0, payloadSize-id.length) + id;
  const signature = `server${server}`;

  if (modeIsHTTP) {
    const url = `http://${addr}/${signature}`;

    const res = http.post(url, payload);
    check(res, {
      "status is 200": (r) => r.status === 200,
      "processed by correct backend": (r) => r.headers["Signature"] == signature,
      "benchmark is performance": (r) => r.headers["Benchmark"] === "performance",
      "body is the same": (r) => r.body === payload,
    });
  }
  else {
    if (__ITER == 0) {
      client.connect('127.0.0.1:50051', { plaintext: true });
    }

    const data = {
      agent: "k6",
      benchmark: "test",
      payload: payload,
    }

    const res = client.invoke("echo.Echo/Send", data);
    check(res, {
      "status is OK": (r) => r && r.status === StatusOK,
      "processed by correct backend": (r) => r.message.signature == signature,
      "benchmark is performance": (r) => r.message.benchmark === "performance",
      "body is the same": (r) => r.message.payload === payload,
    });
  }
}
