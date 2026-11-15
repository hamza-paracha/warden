module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    roots: ['<rootDir>/__tests__', '<rootDir>/src'],
    testMatch: ['**/__tests__/**/*.test.ts', '**/?(*.)+(spec|test).ts'],
    transform: {
        '^.+\\.ts$': 'ts-jest',
    },
    collectCoverageFrom: [
        'src/**/*.ts',
        '!src/**/*.test.ts',
        '!src/**/*.spec.ts',
        '!src/index.ts',
    ],
    coverageThreshold: {
        // Keep the verifier covered independently of legacy paths.
        './src/verification/index.ts': {
            branches: 85,
            functions: 90,
            lines: 90,
            statements: 90,
        },
        global: {
            branches: 15,
            functions: 20,
            lines: 15,
            statements: 15,
        },
    },
    moduleFileExtensions: ['ts', 'js', 'json'],
    verbose: true,
    testPathIgnorePatterns: ['/node_modules/', '/dist/', '/src/core/'],
    transformIgnorePatterns: [
        'node_modules/(?!(chalk|ora|@octokit)/)'
    ],
};
