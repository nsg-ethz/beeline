import { url, requestTo } from "./common.js";

const rate = __ENV.RATE || 20000;
const vus = __ENV.VUS || 3000;
const headerLength = __ENV.LEN || 1024;
const randomHeader = "a".repeat(Math.max(0, headerLength));

export const options = {
    scenarios: {
        mutate: {
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
    if (randomHeader.length > 0) {
        const headers = {
            test: randomHeader,
        };
        requestTo(url, headers);
    } else {
        requestTo(url);
    }
}
