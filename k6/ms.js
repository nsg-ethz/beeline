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
                { target: 3500, duration: "100s" },
                { target: 3500, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
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
