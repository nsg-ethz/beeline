import { randomRequest } from "./common.js";

const rate = __ENV.RATE || 10000;

export const options = {
  scenarios: {
    rps: {
      executor: "ramping-arrival-rate",
      stages: [
        { duration: "5s", target: rate },
        { duration: "55s", target: rate },
      ],
      preAllocatedVUs: 3000,
    }
  }
};

export default randomRequest;