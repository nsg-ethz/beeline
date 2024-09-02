import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    stress: {
      executor: "constant-arrival-rate",
      rate: 30000,
      duration: "2m",
      preAllocatedVUs: 2000,
    }
  }
};

export default randomRequest;