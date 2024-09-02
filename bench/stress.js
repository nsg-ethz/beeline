import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    randomRequests: {
      executor: "constant-arrival-rate",
      rate: 1000,
      duration: "2m",
      preAllocatedVUs: 5000,
    }
  }
};

export default function () {
  randomRequest();
}