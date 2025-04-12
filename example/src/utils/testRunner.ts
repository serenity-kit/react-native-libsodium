import { isEqualUint8Array } from './isEqualUint8Array';

type TestCallback = () => void | Promise<void>;

type Test = {
  id: string;
  description: string;
  execute: TestCallback;
};

class TestFailure extends Error {}

export type TestResult =
  | { success: true; test: Test; descriptions: string[] }
  | { success: false; test: Test; error: unknown; descriptions: string[] };

type TestSuiteEntry =
  | { type: 'test'; test: Test }
  | { type: 'suite'; suite: TestSuite };

type TestSuite = { description: string; children: TestSuiteEntry[] };

class TestRunner {
  private constructor(
    private nextId: number = 1,
    private stack: TestSuite[] = [{ description: '', children: [] }]
  ) {}
  static empty() {
    return new TestRunner();
  }
  registerTest(props: Omit<Test, 'id'>) {
    const id = '_' + this.nextId++;
    this.suite().children.push({ type: 'test', test: { ...props, id } });
  }
  suite() {
    const suite = this.stack[this.stack.length - 1];
    if (!suite) throw new TypeError();
    return suite;
  }
  push(description: string) {
    const current = this.suite();
    const child: TestSuite = { description, children: [] };
    current.children.push({ type: 'suite', suite: child });
    this.stack.push(child);
  }
  pop() {
    if (this.stack.length < 2) throw new Error('cannot pop root');
    this.stack.pop();
  }
  root() {
    const root = this.stack[0];
    if (!root) throw new TypeError();
    return root;
  }
  private async runSuite(
    suite: TestSuite,
    results: TestResult[],
    descriptions: string[]
  ) {
    for (let child of suite.children) {
      if (child.type === 'suite') {
        await this.runSuite(
          child.suite,
          results,
          descriptions.concat([child.suite.description])
        );
      } else {
        try {
          await child.test.execute();
          results.push({ success: true, test: child.test, descriptions });
        } catch (err) {
          results.push({
            success: false,
            test: child.test,
            error: err,
            descriptions,
          });
        }
      }
    }
  }
  async runAll() {
    const results: TestResult[] = [];
    await this.runSuite(this.root(), results, []);
    return results;
  }
}

const globalRegistry = TestRunner.empty();

export function test(description: string, callback: TestCallback) {
  globalRegistry.registerTest({ description, execute: callback });
}

class Expect {
  constructor(
    readonly actual: unknown,
    private inverse: boolean = false
  ) {}
  get not() {
    this.inverse = !this.inverse;
    return this;
  }
  private check(f: () => boolean) {
    const result = f();
    return (result && !this.inverse) || (!result && this.inverse);
  }
  private fail(regular: string, inverse: string) {
    if (this.inverse) {
      throw new TestFailure(inverse);
    } else {
      throw new TestFailure(regular);
    }
  }
  toBe(expected: unknown) {
    if (this.check(() => this.actual !== expected)) {
      this.fail(
        `actual "${this.actual}" is not strictly equal to expected "${expected}"`,
        `actual "${this.actual}" is strictly equal to expected "${expected}"`
      );
    }
  }
  toEqual(expected: unknown) {
    if (
      this.check(() => {
        if (
          this.actual instanceof Uint8Array ||
          expected instanceof Uint8Array
        ) {
          // @ts-expect-error
          return !isEqualUint8Array(this.actual, expected);
        }

        return this.actual !== expected;
      })
    ) {
      this.fail(
        `actual "${this.actual}" is not strictly equal to expected "${expected}"`,
        `actual "${this.actual}" is strictly equal to expected "${expected}"`
      );
    }
  }
  toBeUndefined() {
    if (this.check(() => this.actual !== undefined)) {
      this.fail(
        `expected undefined but got "${this.actual}"`,
        'expected a value but got undefined'
      );
    }
  }
  toThrow(msg?: string) {
    if (typeof this.actual !== 'function') {
      throw new TypeError('.toThrow requires callback function');
    }
    if (this.inverse) {
      throw new TypeError('.not inversion of .toThrow currently not supported');
    }

    try {
      this.actual();
    } catch (err) {
      if (!(err instanceof Error)) {
        throw new TestFailure('error is not an instanceof Error');
      }
      if (msg && !err.message.includes(msg)) {
        throw new TestFailure(
          `error message "${err.message}" does not match substring "${msg}"`
        );
      }
    }
  }
}

export function expect(actual: unknown) {
  return new Expect(actual);
}

export function runTests() {
  return globalRegistry.runAll();
}

export function describe(description: string, callback: () => void) {
  globalRegistry.push(description);
  callback();
  globalRegistry.pop();
}
