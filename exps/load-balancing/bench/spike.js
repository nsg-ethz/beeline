import http from 'k6/http';
import { check } from 'k6';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  // Key configurations for spike in this section
  stages: [
    { duration: '2m', target: 2000 }, // fast ramp-up to a high point
    { duration: '1m', target: 0 }, // quick ramp-down to 0 users
  ],
};

export default function () {
  const server = randomIntBetween(1, 4);
  const url = `http://127.0.0.1:3000/server${server}`;
  const res = http.get(url);

  check(res, {
    'GET status is 200': (r) => res.status === 200,
  });
}