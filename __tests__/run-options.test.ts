import { parseNonNegativeInteger, parsePositiveInteger } from '../src/utils/run-options';

it.each(['-1', '1.5', '2oops', 'NaN', 'Infinity', '9007199254740992'])(
    'rejects invalid numeric arguments: %s',
    (value) => {
        expect(() => parseNonNegativeInteger(value)).toThrow();
    }
);
it('accepts zero fixes but requires a bounded positive timeout', () => {
    expect(parseNonNegativeInteger('0')).toBe(0);
    expect(parsePositiveInteger('30000')).toBe(30000);
    expect(() => parsePositiveInteger('0')).toThrow();
    expect(() => parsePositiveInteger('2147483648')).toThrow();
});
