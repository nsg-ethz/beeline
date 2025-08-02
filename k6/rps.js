import { request } from "./common.js";

const rate = __ENV.RATE || 10000;
const vus = __ENV.VUS || 3000;

export const options = {
    scenarios: {
        rps: {
            executor: "constant-arrival-rate",
            duration: "5m",
            rate: rate,
            preAllocatedVUs: vus,
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

export default request;
