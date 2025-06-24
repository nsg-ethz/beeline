import { url, requestTo, randomData, payloadSize } from "./common.js";
import exec from "k6/execution";

const rate = __ENV.RATE || 20000;
const vus = __ENV.VUS || 3000;
const maxHeaderLength = __ENV.LEN || 1024;

const statusLine = "POST / HTTP/1.1";
const maxHeaderValueLength =
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
    "test".length -
    4 -
    2;

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
    const randomHeaderLength = Math.round(
        exec.scenario.progress * maxHeaderValueLength,
    );
    const randomHeader = randomData.substring(0, randomHeaderLength);
    const headers = { test: randomHeader };
    requestTo(url, headers);
}
