export function createCleanupTransfer() {
  let transferred = false;
  return Object.freeze({
    get transferred() { return transferred; },
    transfer(register) {
      if (typeof register !== 'function') throw new TypeError('register must be a function');
      if (transferred) throw new Error('cleanup ownership was already transferred');
      register();
      transferred = true;
    },
  });
}

export async function runExhaustiveCleanup(tasks, label) {
  if (!Array.isArray(tasks) || tasks.length === 0 ||
      tasks.some((task) => typeof task !== 'function')) {
    throw new TypeError('cleanup tasks must be a non-empty function array');
  }
  const outcomes = await Promise.allSettled(tasks.map((task) => task()));
  const failures = outcomes.filter((outcome) => outcome.status === 'rejected')
    .map((outcome) => outcome.reason);
  if (failures.length > 0) {
    throw new AggregateError(failures, label);
  }
}
