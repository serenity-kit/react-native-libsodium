import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { fixupConfigRules, fixupPluginRules } from '@eslint/compat';
import { FlatCompat } from '@eslint/eslintrc';
import ftFlowPluginImport from 'eslint-plugin-ft-flow';
import prettierPluginImport from 'eslint-plugin-prettier';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ftFlowPlugin = ftFlowPluginImport.default ?? ftFlowPluginImport;
const prettierPlugin = prettierPluginImport.default ?? prettierPluginImport;

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

const compatConfigs = compat.extends('@react-native/eslint-config', 'prettier');
const fixedCompatConfigs = fixupConfigRules(
  compatConfigs.map((config) => {
    if (!config.plugins) {
      return config;
    }

    const fixedPlugins = Object.fromEntries(
      Object.entries(config.plugins).map(([name, plugin]) => {
        if (name === 'react' || name === 'ft-flow') {
          return [name, fixupPluginRules(plugin)];
        }

        return [name, plugin];
      })
    );

    return { ...config, plugins: fixedPlugins };
  })
);

const ftFlowRuleOverrides = Object.fromEntries(
  Object.keys(ftFlowPlugin.rules || {}).map((rule) => [
    `ft-flow/${rule}`,
    'off',
  ])
);

export default [
  {
    ignores: ['lib/**', 'node_modules/**'],
  },
  ...fixedCompatConfigs,
  {
    plugins: {
      prettier: prettierPlugin,
    },
    rules: {
      ...ftFlowRuleOverrides,
      'prettier/prettier': [
        'error',
        {
          quoteProps: 'consistent',
          singleQuote: true,
          tabWidth: 2,
          trailingComma: 'es5',
          useTabs: false,
        },
      ],
    },
  },
];
