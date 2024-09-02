import { check } from 'k6';
import http from 'k6/http';
import exec from 'k6/execution';
import { randomIntBetween, randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  stages: [
    { duration: '2s', target: 1 },
    // { duration: '2m', target: 200 }, 
    // { duration: '1m', target: 0 }, 
  ],
};

export default function () {
  const payload_size = __ENV.PAYLOAD_SIZE || 1024;
  const server = randomIntBetween(1, 4);
  const signature = `server${server}`;
  const url = `http://127.0.0.1:3000/${signature}`;
  const data = JSON.stringify({ "text": randomString(payload_size) });
  const res = http.post(url, data);

  let passed = check(res, {
    'GET status is 200': (r) => r.status === 200,
    'processed by correct backend': (r) => r.headers["Signature"] == signature,
    'body is the same': (r) => r.body === data
  });

  const abortOnFail = __ENV.ABORT_ON_FAIL || false;
  if (!passed && abortOnFail) {
    exec.test.abort();
  }
}