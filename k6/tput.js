import { randomRequest } from "./common.js";

const vus = __ENV.VUS || 3000;

export const options = {
    scenarios: {
        tput: {
            executor: "constant-vus",
            duration: "60s",
            vus: vus,
        },
    },
    thresholds: {
        http_req_failed: [{ threshold: "rate<0.01", abortOnFail: true }],
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

export default randomRequest;
