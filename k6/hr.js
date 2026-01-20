import { check } from "k6";
import exec from "k6/execution";
import http from "k6/http";
import { randomIntBetween } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

export const options = {
    scenarios: {
        recommendations: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 200,
            stages: [
                { target: 15000, duration: "100s" },
                { target: 15000, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
    },
    discardResponseBodies: true,
    insecureSkipTLSVerify: true,
};

const dest = __ENV.URL || "https://moonshine:9991";

export default () => {
    const args = ["dis", "rate", "price"];
    var require = args[randomIntBetween(0, args.length - 1)];

    const lat = 38.0235 + (randomIntBetween(0, 481) - 240.5) / 1000.0;
    const lon = -122.095 + (randomIntBetween(0, 325) - 157.0) / 1000.0;

    const params = {
        tags: { name: "recommendations" },
        timeout: "3s",
    };
    const res = http.get(
        `${dest}/recommendations?require=${require}&lat=${lat}&lon=${lon}`,
        params,
    );

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
