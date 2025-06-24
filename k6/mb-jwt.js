import { generateWebToken, url, requestTo } from "./common.js";
const rate = __ENV.RATE || 20000;
const vus = __ENV.VUS || 3000;

export const options = {
    scenarios: {
        rps: {
            executor: "constant-arrival-rate",
            duration: "1m",
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

export default function () {
    const headers = {
        Authorization: "Bearer " + generateWebToken(true),
    };
    requestTo(url, headers);
}
