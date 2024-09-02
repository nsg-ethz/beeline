import { check } from 'k6';
import http from 'k6/http';
import exec from 'k6/execution';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.3.0/index.js';
import { Counter } from 'k6/metrics';

const payload_size = __ENV.PAYLOAD_SIZE || 1024;
const data = randomString(payload_size);

const backends = [
  new Counter('backend1'),
  new Counter('backend2'),
  new Counter('backend3'),
  new Counter('backend4')
];

export function randomRequest() {
  const server = __ENV.BACKEND || randomIntBetween(1, 4);
  const id = exec.scenario.iterationInInstance.toString();
  requestTo(server, id);
}

export function requestTo(server, id) {
  const signature = `server${server}`;

  var url = null;
  const direct = (__ENV.DIRECT || "0") == "1";
  if (direct) {
    url = `http://10.0.${server}.1:8000/${signature}`;
  }
  else {
    url = `http://10.0.5.1:3000/${signature}`;
  }

  backends[server-1].add(1);

  let payload = data;
  if (id) {
    payload = data.substring(0, payload_size-id.length) + id;
  }

  const res = http.post(url, payload);
  let passed = check(res, {
    "status is 200": (r) => r.status === 200,
    "processed by correct backend": (r) => r.headers["Signature"] == signature,
    "body is the same": (r) => r.body === payload
  });

  let abortOnFail = __ENV.ABORT_ON_FAIL || "0";
  abortOnFail = ["1", "true"].includes(abortOnFail.toLowerCase());
  if (!passed && abortOnFail) {
    exec.test.abort();
  }
}
