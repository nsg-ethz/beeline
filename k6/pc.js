import { request } from "./common.js";

const vus = __ENV.VUS || 100;

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
    summaryTrendStats: [
        "min",
        "med",
        "max",
        "avg",
        "p(25)",
        "p(75)",
        "p(95)",
        "p(99)",
    ],
};

export default request;
