import http from 'k6/http';
import { check } from 'k6';
import { randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

export const options = {
  stages: [
    { duration: '1m', target: 1000 }, // traffic ramp-up from 1 to a higher 200 users over 10 minutes.
    { duration: '10m', target: 1000 }, // stay at higher 200 users for 30 minutes
    { duration: '5m', target: 0 }, // ramp-down to 0 users
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