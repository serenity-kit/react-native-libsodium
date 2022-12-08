import type {
  StringOutputFormat,
  Uint8ArrayOutputFormat,
} from 'libsodium-wrappers';

export type OutputFormat =
  | StringOutputFormat
  | Uint8ArrayOutputFormat
  | null
  | undefined;
