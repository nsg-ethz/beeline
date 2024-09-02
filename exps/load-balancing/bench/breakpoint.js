import { check } from 'k6';
import http from 'k6/http';
import exec from 'k6/execution';
import { randomIntBetween, randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  executor: 'ramping-arrival-rate', //Assure load increase if the system slows
  stages: [
    { duration: '2m', target: 10000 }, // just slowly ramp-up to a HUGE load
  ],
};

export default function () {
  const server = randomIntBetween(1, 4);
  const url = `http://127.0.0.1:3000/server${server}`;
  const data = JSON.stringify({ "text": randomString(1025) });
  const res = http.post(url, data);

  let passed = check(res, {
    'GET status is 200': (r) => res.status === 200,
    'body is the same': (r) => res.body === data
  });

  if (!passed) {
    exec.test.abort(`${data} !== ${res.body}`)
    exec.test.abort('status code was *not* 200');
  }
}