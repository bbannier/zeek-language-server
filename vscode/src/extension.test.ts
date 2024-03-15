import { checkDependencies } from "./extension";

// jest.mock('./extension');

test("checkDependencies", async () => {
  await checkDependencies();
});
