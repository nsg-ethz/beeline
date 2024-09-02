import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    stress: {
      executor: "constant-arrival-rate",
      rate: 5000,
      duration: "2m",
      preAllocatedVUs: 100,
    }
  }
};

export default function () {
  randomRequest();
}