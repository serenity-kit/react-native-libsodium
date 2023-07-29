const { createRunOncePlugin } = require('@expo/config-plugins');
// keeping the name, and version in sync with it's package
const pkg = require('./package.json');

const withNothing = (config) => {
  return config;
};

module.exports = createRunOncePlugin(
  // the plugin to guard
  withNothing,
  // an identifier used to track if the plugin has already been run
  pkg.name,
  // optional version property
  pkg.version
);
