import {
  crypto_secretstream_xchacha20poly1305_ABYTES,
  crypto_secretstream_xchacha20poly1305_HEADERBYTES,
  crypto_secretstream_xchacha20poly1305_KEYBYTES,
  crypto_secretstream_xchacha20poly1305_TAG_FINAL,
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
  crypto_secretstream_xchacha20poly1305_TAG_PUSH,
  crypto_secretstream_xchacha20poly1305_TAG_REKEY,
  crypto_secretstream_xchacha20poly1305_init_pull,
  crypto_secretstream_xchacha20poly1305_init_push,
  crypto_secretstream_xchacha20poly1305_keygen,
  crypto_secretstream_xchacha20poly1305_pull,
  crypto_secretstream_xchacha20poly1305_push,
  to_string,
} from 'react-native-libsodium';
import { expect, test } from '../utils/testRunner';

test('crypto_secretstream_xchacha20poly1305 constants', () => {
  expect(crypto_secretstream_xchacha20poly1305_ABYTES).toEqual(17);
  expect(crypto_secretstream_xchacha20poly1305_HEADERBYTES).toEqual(24);
  expect(crypto_secretstream_xchacha20poly1305_KEYBYTES).toEqual(32);
  expect(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE).toEqual(0);
  expect(crypto_secretstream_xchacha20poly1305_TAG_PUSH).toEqual(1);
  expect(crypto_secretstream_xchacha20poly1305_TAG_REKEY).toEqual(2);
  expect(crypto_secretstream_xchacha20poly1305_TAG_FINAL).toEqual(3);
});

test('crypto_secretstream_xchacha20poly1305 push and pull round-trip', () => {
  const key = crypto_secretstream_xchacha20poly1305_keygen();
  expect(key.length).toEqual(crypto_secretstream_xchacha20poly1305_KEYBYTES);

  const { state, header } =
    crypto_secretstream_xchacha20poly1305_init_push(key);
  expect(header.length).toEqual(
    crypto_secretstream_xchacha20poly1305_HEADERBYTES
  );

  const additionalDataBytes = new Uint8Array([7, 0, 255, 42]);
  const chunk1 = crypto_secretstream_xchacha20poly1305_push(
    state,
    'chunk one',
    null,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  );
  expect(chunk1.length).toEqual(
    'chunk one'.length + crypto_secretstream_xchacha20poly1305_ABYTES
  );
  const chunk2 = crypto_secretstream_xchacha20poly1305_push(
    state,
    new Uint8Array([1, 2, 3]),
    additionalDataBytes,
    crypto_secretstream_xchacha20poly1305_TAG_PUSH
  );
  const chunk3 = crypto_secretstream_xchacha20poly1305_push(
    state,
    'chunk three',
    'the additional data',
    crypto_secretstream_xchacha20poly1305_TAG_REKEY
  );
  const chunk4 = crypto_secretstream_xchacha20poly1305_push(
    state,
    'the last chunk',
    null,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL
  );

  const pullState = crypto_secretstream_xchacha20poly1305_init_pull(
    header,
    key
  );
  const result1 = crypto_secretstream_xchacha20poly1305_pull(
    pullState,
    chunk1,
    null
  );
  if (result1 === false) {
    throw new Error('pull of chunk1 failed');
  }
  expect(to_string(result1.message)).toEqual('chunk one');
  expect(result1.tag).toEqual(
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  );

  // pulling with a missing or wrong additional_data must fail and must not
  // advance the state
  expect(
    crypto_secretstream_xchacha20poly1305_pull(pullState, chunk2, null)
  ).toEqual(false);
  expect(
    crypto_secretstream_xchacha20poly1305_pull(
      pullState,
      chunk2,
      new Uint8Array([7, 0, 255, 43])
    )
  ).toEqual(false);
  const result2 = crypto_secretstream_xchacha20poly1305_pull(
    pullState,
    chunk2,
    additionalDataBytes
  );
  if (result2 === false) {
    throw new Error('pull of chunk2 failed');
  }
  expect(result2.message).toEqual(new Uint8Array([1, 2, 3]));
  expect(result2.tag).toEqual(crypto_secretstream_xchacha20poly1305_TAG_PUSH);

  const result3 = crypto_secretstream_xchacha20poly1305_pull(
    pullState,
    chunk3,
    'the additional data'
  );
  if (result3 === false) {
    throw new Error('pull of chunk3 failed');
  }
  expect(to_string(result3.message)).toEqual('chunk three');
  expect(result3.tag).toEqual(crypto_secretstream_xchacha20poly1305_TAG_REKEY);

  const result4 = crypto_secretstream_xchacha20poly1305_pull(
    pullState,
    chunk4,
    null
  );
  if (result4 === false) {
    throw new Error('pull of chunk4 failed');
  }
  expect(to_string(result4.message)).toEqual('the last chunk');
  expect(result4.tag).toEqual(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
});

test('crypto_secretstream_xchacha20poly1305_pull failures', () => {
  const key = crypto_secretstream_xchacha20poly1305_keygen();
  const { state, header } =
    crypto_secretstream_xchacha20poly1305_init_push(key);
  const chunk1 = crypto_secretstream_xchacha20poly1305_push(
    state,
    'chunk one',
    null,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
  );
  const chunk2 = crypto_secretstream_xchacha20poly1305_push(
    state,
    'chunk two',
    null,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL
  );

  // truncated ciphertext must fail
  const truncationState = crypto_secretstream_xchacha20poly1305_init_pull(
    header,
    key
  );
  expect(
    crypto_secretstream_xchacha20poly1305_pull(
      truncationState,
      chunk1.slice(0, chunk1.length - 1),
      null
    )
  ).toEqual(false);

  // pulling the chunks out of order must fail
  const reorderState = crypto_secretstream_xchacha20poly1305_init_pull(
    header,
    key
  );
  expect(
    crypto_secretstream_xchacha20poly1305_pull(reorderState, chunk2, null)
  ).toEqual(false);

  // a ciphertext shorter than ABYTES can't contain a message at all
  const tooShortState = crypto_secretstream_xchacha20poly1305_init_pull(
    header,
    key
  );
  expect(() => {
    crypto_secretstream_xchacha20poly1305_pull(
      tooShortState,
      chunk1.slice(0, crypto_secretstream_xchacha20poly1305_ABYTES - 1),
      null
    );
  }).toThrow('cipher is too short');
});

test('crypto_secretstream_xchacha20poly1305 invalid input', () => {
  const key = crypto_secretstream_xchacha20poly1305_keygen();
  const { state, header } =
    crypto_secretstream_xchacha20poly1305_init_push(key);

  expect(() => {
    crypto_secretstream_xchacha20poly1305_init_push(key.slice(0, 5));
  }).toThrow('invalid key length');
  expect(() => {
    crypto_secretstream_xchacha20poly1305_init_pull(header.slice(0, 5), key);
  }).toThrow('invalid header length');
  expect(() => {
    crypto_secretstream_xchacha20poly1305_init_pull(header, key.slice(0, 5));
  }).toThrow('invalid key length');
  expect(() => {
    crypto_secretstream_xchacha20poly1305_push(
      state,
      'message',
      null,
      null as unknown as number
    );
  }).toThrow('tag cannot be null or undefined');
  expect(() => {
    crypto_secretstream_xchacha20poly1305_push(state, 'message', null, -1);
  }).toThrow('tag must be an unsigned integer');
});
