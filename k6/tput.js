import { randomRequest } from "./common.js";

export const options = {
  scenarios: {
    tput: {
      executor: "constant-vus",
      duration: "60s",
      vus: 1000,
    }
  }
};

export default randomRequest;