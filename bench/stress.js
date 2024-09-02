import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    stress: {
      executor: "constant-arrival-rate",
      rate: __ENV.RATE,
      duration: "2m",
      preAllocatedVUs: 3000,
    }
  }
};

export default randomRequest;