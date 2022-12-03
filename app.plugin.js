const { createRunOncePlugin } = require('@expo/config-plugins');
const packageJson = require('./package.json');

const withNothing = (config) => {
  return config;
};

module.exports = createRunOncePlugin(
  withNothing,
  packageJson.name,
  packageJson.version
);
