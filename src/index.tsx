declare global {
  function multiply(a: number, b: number): number;
  function from_base64(value: string, variant: number): string;
  function to_base64(value: string, variant: number): string;
}

export const multiply = global.multiply;

export const from_base64 = global.from_base64;
export const to_base64 = global.to_base64;
