import { url, requestTo, payloadSize } from "./common.js";
import { randomString } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

const rate = __ENV.RATE || 20000;
const vus = __ENV.VUS || 3000;
const maxHeaderLength = __ENV.LEN || 1024;

const statusLine = "POST / HTTP/1.1";
const randomHeaderLength =
    maxHeaderLength -
    statusLine.length -
    "host".length -
    url.replace("http://", "").length -
    4 -
    "user-agent".length -
    "Grafana k6/1.0.0".length -
    4 -
    "content-length".length -
    payloadSize.toString().length -
    4 -
    "Authorization: Bearer ".length -
    2;
const randomHeader = randomString(randomHeaderLength);

export const options = {
    scenarios: {
        parse: {
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
    const headers = { test: randomHeader };
    requestTo(url, headers);
}
