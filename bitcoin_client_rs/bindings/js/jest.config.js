module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/ts'],
  testPathIgnorePatterns: ['<rootDir>/build/'],
};
