import { dest } from "./common.js";
import { check } from "k6";
import http from "k6/http";
import { randomIntBetween } from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

export const options = {
    scenarios: {
        compose_post: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 1000,
            stages: [
                { target: 5000, duration: "100s" },
                { target: 5000, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
    },
    discardResponseBodies: true,
};

export default () => {
    const params = ["dis", "rate", "price"];
    var require = params[randomIntBetween(0, params.length - 1)];

    const lat = 38.0235 + (randomIntBetween(0, 481) - 240.5) / 1000.0;
    const lon = -122.095 + (randomIntBetween(0, 325) - 157.0) / 1000.0;

    const res = http.get(
        `${dest}/recommendations?require=${require}&lat=${lat}&lon=${lon}`,
    );

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
