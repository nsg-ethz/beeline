import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    stress: {
      executor: "constant-arrival-rate",
      rate: __ENV.RATE || 10000,
      duration: "1m",
      preAllocatedVUs: 3000,
    }
  }
};

export default randomRequest;