import { requestTo } from "./common.js";

export const options = {
  scenarios: {
    debug: {
      executor: "shared-iterations",
    }
  }
};

export default function() {
    requestTo(1);
}