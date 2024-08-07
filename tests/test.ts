// /Users/anmolnoor/Developer/authWAPI/tests/test.ts

const sum = (a: number, b: number): number => a + b;
const subtract = (a: number, b: number): number => a - b;

describe('Math functions', () => {
  test('sum adds two positive numbers', () => {
    expect(sum(1, 2)).toBe(3);
  });

  test('sum adds positive and negative number', () => {
    expect(sum(1, -2)).toBe(-1);
  });

  test('sum adds two negative numbers', () => {
    expect(sum(-1, -2)).toBe(-3);
  });

  test('sum adds zero and a number', () => {
    expect(sum(0, 5)).toBe(5);
  });

  test('sum adds two zeros', () => {
    expect(sum(0, 0)).toBe(0);
  });

  test('subtract subtracts two positive numbers', () => {
    expect(subtract(5, 3)).toBe(2);
  });

  test('subtract subtracts positive and negative number', () => {
    expect(subtract(5, -3)).toBe(8);
  });

  test('subtract subtracts two negative numbers', () => {
    expect(subtract(-5, -3)).toBe(-2);
  });

  test('subtract subtracts zero and a number', () => {
    expect(subtract(0, 5)).toBe(-5);
  });

  test('subtract subtracts two zeros', () => {
    expect(subtract(0, 0)).toBe(0);
  });
});
