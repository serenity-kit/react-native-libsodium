declare global {
  function multiply(a: number, b: number): number;
}

export const multiply = global.multiply;
