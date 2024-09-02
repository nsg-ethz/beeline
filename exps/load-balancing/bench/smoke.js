import { check } from 'k6';
import http from 'k6/http';
import exec from 'k6/execution';
import { randomIntBetween, randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  stages: [
    { duration: '1m', target: 1000 }, // traffic ramp-up from 1 to a higher 200 users over 10 minutes.
    { duration: '10m', target: 1000 }, // stay at higher 200 users for 30 minutes
    { duration: '5m', target: 0 }, // ramp-down to 0 users
  ],
};

export default function () {
  const server = randomIntBetween(1, 4);
  const signature = `server${server}`;
  const url = `http://127.0.0.1:3000/${signature}`;
  const data = JSON.stringify({ "text": randomString(1024) });
  const res = http.post(url, data);

  let passed = check(res, {
    'GET status is 200': (r) => r.status === 200,
    'processed by correct backend': (r) => r.headers["Signature"] == signature,
    'body is the same': (r) => r.body === data
  });

  if (!passed) {
    exec.test.abort(`${data} !== ${res.body}`)
    exec.test.abort('status code was *not* 200');
  }
}