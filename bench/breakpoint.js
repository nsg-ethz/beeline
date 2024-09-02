import { randomRequest } from "./common";

export const options = {
  scenarios: {
    breakpoint: {
      executor: "ramping-arrival-rate",
      stages: [
        { duration: "10m", target: 100000 }, 
      ],
    }
  }
};

export default randomRequest;