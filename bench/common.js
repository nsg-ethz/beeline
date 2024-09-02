import { check } from 'k6';
import http from 'k6/http';
import exec from 'k6/execution';
import { randomIntBetween, randomString } from 'https://jslib.k6.io/k6-utils/1.3.0/index.js';

export function randomRequest() {
  const payload_size = __ENV.PAYLOAD_SIZE || 1024;
  const server = randomIntBetween(1, 4);
  const signature = `server${server}`;
  const url = `http://127.0.0.1:3000/${signature}`;
  // const url = `http://10.0.${server}.1:8000/${signature}`;
  const data = JSON.stringify({ "text": randomString(payload_size) });
  const res = http.post(url, data);

  let passed = check(res, {
    'GET status is 200': (r) => r.status === 200,
    'processed by correct backend': (r) => r.headers["Signature"] == signature,
    'body is the same': (r) => r.body === data
  });

  let abortOnFail = __ENV.ABORT_ON_FAIL || "0";
  abortOnFail = ["1", "true"].includes(abortOnFail.toLowerCase());
  if (!passed && abortOnFail) {
    exec.test.abort();
  }
}
