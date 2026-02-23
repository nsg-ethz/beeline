import { dest } from "./common.js";
import { check } from "k6";
import http from "k6/http";
import { randomIntBetween } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

const vus = __ENV.VUS || 3000;
const fullArgument = "b".repeat(16384);

export const options = {
    scenarios: {
        mixed_workload: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 200,
            stages: [
                { target: 20000, duration: "200s" },
                { target: 20000, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
    },
    discardResponseBodies: true,
};

export default () => {
    const echos = randomIntBetween(1, 6);
    const argumentSize = randomIntBetween(1, 10000);
    const argument = fullArgument.slice(0, argumentSize);

    const params = {
        tags: { name: "echo" },
        headers: { test: argument },
        timeout: "3s",
    };

    const url = http.url`${dest}/echo/${echos}`;
    const res = http.post(url, params);
    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
