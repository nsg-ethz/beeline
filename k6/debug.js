import exec from "k6/execution";
import { requestTo } from "./common.js";

export const options = {
    scenarios: {
        debug: {
            executor: "shared-iterations",
        },
    },
};

export default function () {
    const url = __ENV.URL || "http://127.0.0.1:3000";
    const backend = Number(__ENV.BACKEND || "1");
    const passed = requestTo(url, backend);
    let abortOnFail = __ENV.ABORT_ON_FAIL || "1";
    abortOnFail = ["1", "true"].includes(abortOnFail.toLowerCase());
    if (!passed && abortOnFail) {
        exec.test.abort();
    }
}
