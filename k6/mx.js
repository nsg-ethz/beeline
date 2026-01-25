import { dest } from "./common.js";
import { check } from "k6";
import http from "k6/http";
import { randomIntBetween } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

const vus = __ENV.VUS || 3000;
const fullArgument = "b".repeat(16384);

export const options = {
    scenarios: {
        tput: {
            executor: "ramping-vus",
            startVUs: 0,
            stages: [
                { duration: "5s", target: vus },
                { duration: "60s", target: vus },
            ],
            gracefulRampDown: "3s",
        },
    },
};

export default () => {
    const echos = randomIntBetween(1, 6);
    const argumentSize = randomIntBetween(100, 16384);
    const argument = fullArgument.slice(0, argumentSize);

    const params = {
        tags: { name: "echo" },
        timeout: "3s",
    };

    const url = `${dest}/echo/${echos}?arg=${argument}`;
    const res = http.post(url, params);
    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
