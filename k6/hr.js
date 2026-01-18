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
                { target: 10000, duration: "100s" },
                { target: 10000, duration: "5s" },
            ],
            gracefulStop: "3s",
        },
    },
    discardResponseBodies: true,
    insecureSkipTLSVerify: true,
};

const dest = __ENV.URL || "https://moonshine:9991";

function getRecommendations() {
    const args = ["dis", "rate", "price"];
    var require = args[randomIntBetween(0, args.length - 1)];

    const lat = 38.0235 + (randomIntBetween(0, 481) - 240.5) / 1000.0;
    const lon = -122.095 + (randomIntBetween(0, 325) - 157.0) / 1000.0;

    const params = {
        tags: { name: "recommendations" },
    };
    const res = http.get(
        `${dest}/recommendations?require=${require}&lat=${lat}&lon=${lon}`,
        params,
    );

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
}

function reserve() {
    const userID = randomIntBetween(0, 500);
    const userName = `Cornell_${userID}`;
    const userPassword = `${userID}${userID}${userID}${userID}${userID}${userID}${userID}${userID}${userID}${userID}`;

    const hotelID = randomIntBetween(1, 80);
    const startDay = randomIntBetween(9, 23);
    const endDay = randomIntBetween(startDay + 1, 24);

    const startDate = `2015-04-${startDay < 10 ? "0" : ""}${startDay}`;
    const endDate = `2015-04-${endDay < 10 ? "0" : ""}${endDay}`;

    const lat = 38.0235 + (randomIntBetween(0, 481) - 240.5) / 1000.0;
    const lon = -122.095 + (randomIntBetween(0, 325) - 157.0) / 1000.0;

    const params = {
        tags: { name: "reserve" },
    };
    const url = `${dest}/reservation?inDate=${startDate}&outDate=${endDate}&lat=${lat}&lon=${lon}&hotelId=${hotelID}&customerName=${userName}&username=${userID}&password=${userPassword}&number=1`;
    const res = http.get(url, params);

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
}

function searchHotel() {
    const startDay = randomIntBetween(9, 23);
    const endDay = randomIntBetween(startDay + 1, 24);

    const startDate = `2015-04-${startDay < 10 ? "0" : ""}${startDay}`;
    const endDate = `2015-04-${endDay < 10 ? "0" : ""}${endDay}`;

    const lat = 38.0235 + (randomIntBetween(0, 481) - 240.5) / 1000.0;
    const lon = -122.095 + (randomIntBetween(0, 325) - 157.0) / 1000.0;

    const params = {
        tags: { name: "search" },
    };
    const url = `${dest}/hotels?inDate=${startDate}&outDate=${endDate}&lat=${lat}&lon=${lon}`;
    const res = http.get(url, params);

    return check(res, {
        "status is 200": (r) => r.status === 200,
    });
}

export default () => {
    getRecommendations();
};
