import { generateWebToken } from "./common.js";
import { check } from "k6";
import http from "k6/http";
import {
    randomString,
    randomIntBetween,
} from "https://jslib.k6.io/k6-utils/1.3.0/index.js";

const randomText = randomString(256);

export const options = {
    scenarios: {
        compose_review: {
            executor: "ramping-arrival-rate",
            preAllocatedVUs: 300,
            stages: [
                { target: 100, duration: "10s" },
                { target: 100, duration: "5m" },
            ],
            gracefulStop: "3s",
        },
    },
    thresholds: {
        http_req_failed: [{ threshold: "rate<0.01" }],
    },
    discardResponseBodies: true,
};

export default () => {
    const userIndex = randomIntBetween(1, 1000);
    const movieIndex = randomIntBetween(1, 1000);

    const username = `username_${userIndex}`;
    const password = `password_${userIndex}`;
    const title = `title_${movieIndex}`;
    const rating = randomIntBetween(0, 10);

    const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Bearer " + generateWebToken(true),
    };
    const params = {
        headers: headers,
        timeout: "3s",
    };

    const body = `username=${username}&password=${password}&title=${title}&rating=${rating}&text=${randomText}`;
    const res = http.post(
        "http://moonshine:8080/wrk2-api/review/compose",
        body,
        params,
    );

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
};
