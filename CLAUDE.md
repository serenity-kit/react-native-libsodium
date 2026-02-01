# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

React Native library providing Libsodium cryptography bindings with an API matching `libsodium-wrappers`. Supports iOS, Android, and Web platforms.

## Build, Test & Development Commands

```bash
yarn                    # Install dependencies (requires Yarn 1.x)
yarn bootstrap          # Install deps + iOS pods for example app
yarn prepack            # Build lib/ output via react-native-builder-bob

yarn typecheck          # TypeScript type checking
yarn lint               # ESLint + Prettier
yarn lint --fix         # Auto-fix formatting
yarn test               # Jest unit tests

# Example App
yarn example start      # Start Metro server
yarn example ios        # Run on iOS
yarn example android    # Run on Android
yarn example web        # Run on Web (http://localhost:8080)

# E2E Testing
yarn test:e2e:web                                  # Playwright web tests
maestro test e2e-tests/maestro-flow-ios.yml       # iOS E2E
maestro test e2e-tests/maestro-flow-android.yml   # Android E2E
```

## Architecture

```
TypeScript Entry (src/index.ts)
           │
    ┌──────┴──────┐
    │             │
 lib.ts      lib.native.ts
 (Web)         (Native)
    │             │
libsodium-    C++ JSI bindings
wrappers JS   to Libsodium C
```

- **Web** (`src/lib.ts`): Wraps `libsodium-wrappers` npm package with lazy loading. Requires `await ready` before use.
- **Native** (`src/lib.native.ts`): Uses JSI to call C++ functions directly. Global `jsi_*` functions declared via TypeScript.
- **C++ JSI** (`cpp/react-native-libsodium.cpp`): ~50+ cryptographic functions bound to Libsodium C library.

## Key Directories

- `src/`: TypeScript source (entry point: `src/index.ts`)
- `lib/`: Built output (auto-generated, do not edit)
- `cpp/`: C++ JSI implementation
- `ios/`, `android/`: Native platform code
- `libsodium/`: Vendored C library and build script
- `example/`: React Native example app for testing
- `example/src/tests/`: Platform test cases (~30 files)
- `e2e-tests/`: Playwright and Maestro test flows

## Adding New Features

1. Implement in both `src/lib.ts` (web) and `src/lib.native.ts` (native)
2. For native: Add JSI declaration in `lib.native.ts` + C++ implementation in `cpp/`
3. Add tests to `example/src/tests/` and register in `example/src/components/TestResults.tsx`
4. Verify tests pass on Web, iOS, and Android

## Updating Libsodium

1. Download new minisig file to `libsodium/`
2. Update version in `libsodium/build.sh`
3. Run: `cd libsodium && ./build.sh`

## Code Style

- 2 spaces, LF endings
- Single quotes, trailing commas (ES5)
- Conventional Commits enforced by Lefthook
