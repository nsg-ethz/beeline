import { randomRequest } from "./common.js";

const vus = __ENV.VUS || 1000;

export const options = {
  scenarios: {
    tput: {
      executor: "constant-vus",
      duration: "60s",
      vus: vus,
    }
  }
};

export default randomRequest;