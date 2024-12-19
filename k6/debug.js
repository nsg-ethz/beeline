import { requestTo } from "./common.js";

export const options = {
    scenarios: {
        debug: {
            executor: "shared-iterations",
        },
    },
};

export default function () {
    const passed = requestTo("http://127.0.0.1:3000", 1);
    let abortOnFail = __ENV.ABORT_ON_FAIL || "1";
    abortOnFail = ["1", "true"].includes(abortOnFail.toLowerCase());
    if (!passed && abortOnFail) {
        exec.test.abort();
    }
}
