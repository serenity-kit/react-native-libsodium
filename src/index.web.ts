import sodium from 'libsodium-wrappers';

sodium.ready.then(() => {
  // get all keys
  // console.log(JSON.stringify(Object.keys(sodium)));

  add = sodium.add;
  base64_variants = sodium.base64_variants;
  compare = sodium.compare;
  from_base64 = sodium.from_base64;
  from_hex = sodium.from_hex;
  from_string = sodium.from_string;
  increment = sodium.increment;
  is_zero = sodium.is_zero;
  // @ts-ignore
  libsodium = sodium.libsodium;
  memcmp = sodium.memcmp;
  memzero = sodium.memzero;
  output_formats = sodium.output_formats;
  pad = sodium.pad;
  unpad = sodium.unpad;
  ready = sodium.ready;
  symbols = sodium.symbols;
  to_base64 = sodium.to_base64;
  to_hex = sodium.to_hex;
  to_string = sodium.to_string;
  crypto_aead_chacha20poly1305_decrypt =
    sodium.crypto_aead_chacha20poly1305_decrypt;
  crypto_aead_chacha20poly1305_decrypt_detached =
    sodium.crypto_aead_chacha20poly1305_decrypt_detached;
  crypto_aead_chacha20poly1305_encrypt =
    sodium.crypto_aead_chacha20poly1305_encrypt;
  crypto_aead_chacha20poly1305_encrypt_detached =
    sodium.crypto_aead_chacha20poly1305_encrypt_detached;
  crypto_aead_chacha20poly1305_ietf_decrypt =
    sodium.crypto_aead_chacha20poly1305_ietf_decrypt;
  crypto_aead_chacha20poly1305_ietf_decrypt_detached =
    sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached;
  crypto_aead_chacha20poly1305_ietf_encrypt =
    sodium.crypto_aead_chacha20poly1305_ietf_encrypt;
  crypto_aead_chacha20poly1305_ietf_encrypt_detached =
    sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached;
  crypto_aead_chacha20poly1305_ietf_keygen =
    sodium.crypto_aead_chacha20poly1305_ietf_keygen;
  crypto_aead_chacha20poly1305_keygen =
    sodium.crypto_aead_chacha20poly1305_keygen;
  crypto_aead_xchacha20poly1305_ietf_decrypt =
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt;
  crypto_aead_xchacha20poly1305_ietf_decrypt_detached =
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
  crypto_aead_xchacha20poly1305_ietf_encrypt =
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt;
  crypto_aead_xchacha20poly1305_ietf_encrypt_detached =
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
  crypto_aead_xchacha20poly1305_ietf_keygen =
    sodium.crypto_aead_xchacha20poly1305_ietf_keygen;
  crypto_auth = sodium.crypto_auth;
  crypto_auth_keygen = sodium.crypto_auth_keygen;
  crypto_auth_verify = sodium.crypto_auth_verify;
  crypto_box_beforenm = sodium.crypto_box_beforenm;
  crypto_box_detached = sodium.crypto_box_detached;
  crypto_box_easy = sodium.crypto_box_easy;
  crypto_box_easy_afternm = sodium.crypto_box_easy_afternm;
  crypto_box_keypair = sodium.crypto_box_keypair;
  crypto_box_open_detached = sodium.crypto_box_open_detached;
  crypto_box_open_easy = sodium.crypto_box_open_easy;
  crypto_box_open_easy_afternm = sodium.crypto_box_open_easy_afternm;
  crypto_box_seal = sodium.crypto_box_seal;
  crypto_box_seal_open = sodium.crypto_box_seal_open;
  crypto_box_seed_keypair = sodium.crypto_box_seed_keypair;
  crypto_generichash = sodium.crypto_generichash;
  crypto_generichash_final = sodium.crypto_generichash_final;
  crypto_generichash_init = sodium.crypto_generichash_init;
  crypto_generichash_keygen = sodium.crypto_generichash_keygen;
  crypto_generichash_update = sodium.crypto_generichash_update;
  crypto_hash = sodium.crypto_hash;
  crypto_kdf_derive_from_key = sodium.crypto_kdf_derive_from_key;
  crypto_kdf_keygen = sodium.crypto_kdf_keygen;
  crypto_kx_client_session_keys = sodium.crypto_kx_client_session_keys;
  crypto_kx_keypair = sodium.crypto_kx_keypair;
  crypto_kx_seed_keypair = sodium.crypto_kx_seed_keypair;
  crypto_kx_server_session_keys = sodium.crypto_kx_server_session_keys;
  crypto_pwhash = sodium.crypto_pwhash;
  crypto_pwhash_str = sodium.crypto_pwhash_str;
  crypto_pwhash_str_needs_rehash = sodium.crypto_pwhash_str_needs_rehash;
  crypto_pwhash_str_verify = sodium.crypto_pwhash_str_verify;
  crypto_scalarmult = sodium.crypto_scalarmult;
  crypto_scalarmult_base = sodium.crypto_scalarmult_base;
  crypto_secretbox_detached = sodium.crypto_secretbox_detached;
  crypto_secretbox_easy = sodium.crypto_secretbox_easy;
  crypto_secretbox_keygen = sodium.crypto_secretbox_keygen;
  crypto_secretbox_open_detached = sodium.crypto_secretbox_open_detached;
  crypto_secretbox_open_easy = sodium.crypto_secretbox_open_easy;
  crypto_secretstream_xchacha20poly1305_init_pull =
    sodium.crypto_secretstream_xchacha20poly1305_init_pull;
  crypto_secretstream_xchacha20poly1305_init_push =
    sodium.crypto_secretstream_xchacha20poly1305_init_push;
  crypto_secretstream_xchacha20poly1305_keygen =
    sodium.crypto_secretstream_xchacha20poly1305_keygen;
  crypto_secretstream_xchacha20poly1305_pull =
    sodium.crypto_secretstream_xchacha20poly1305_pull;
  crypto_secretstream_xchacha20poly1305_push =
    sodium.crypto_secretstream_xchacha20poly1305_push;
  crypto_secretstream_xchacha20poly1305_rekey =
    sodium.crypto_secretstream_xchacha20poly1305_rekey;
  crypto_shorthash = sodium.crypto_shorthash;
  crypto_shorthash_keygen = sodium.crypto_shorthash_keygen;
  crypto_sign = sodium.crypto_sign;
  crypto_sign_detached = sodium.crypto_sign_detached;
  crypto_sign_ed25519_pk_to_curve25519 =
    sodium.crypto_sign_ed25519_pk_to_curve25519;
  crypto_sign_ed25519_sk_to_curve25519 =
    sodium.crypto_sign_ed25519_sk_to_curve25519;
  crypto_sign_final_create = sodium.crypto_sign_final_create;
  crypto_sign_final_verify = sodium.crypto_sign_final_verify;
  crypto_sign_init = sodium.crypto_sign_init;
  crypto_sign_keypair = sodium.crypto_sign_keypair;
  crypto_sign_open = sodium.crypto_sign_open;
  crypto_sign_seed_keypair = sodium.crypto_sign_seed_keypair;
  crypto_sign_update = sodium.crypto_sign_update;
  crypto_sign_verify_detached = sodium.crypto_sign_verify_detached;
  randombytes_buf = sodium.randombytes_buf;
  randombytes_buf_deterministic = sodium.randombytes_buf_deterministic;
  randombytes_close = sodium.randombytes_close;
  randombytes_random = sodium.randombytes_random;
  randombytes_stir = sodium.randombytes_stir;
  randombytes_uniform = sodium.randombytes_uniform;
  sodium_version_string = sodium.sodium_version_string;
  SODIUM_LIBRARY_VERSION_MAJOR = sodium.SODIUM_LIBRARY_VERSION_MAJOR;
  SODIUM_LIBRARY_VERSION_MINOR = sodium.SODIUM_LIBRARY_VERSION_MINOR;
  crypto_aead_chacha20poly1305_ABYTES =
    sodium.crypto_aead_chacha20poly1305_ABYTES;
  crypto_aead_chacha20poly1305_IETF_ABYTES =
    sodium.crypto_aead_chacha20poly1305_IETF_ABYTES;
  crypto_aead_chacha20poly1305_IETF_KEYBYTES =
    sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES;
  crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX =
    sodium.crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX;
  crypto_aead_chacha20poly1305_IETF_NPUBBYTES =
    sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
  crypto_aead_chacha20poly1305_IETF_NSECBYTES =
    sodium.crypto_aead_chacha20poly1305_IETF_NSECBYTES;
  crypto_aead_chacha20poly1305_KEYBYTES =
    sodium.crypto_aead_chacha20poly1305_KEYBYTES;
  crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX =
    sodium.crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX;
  crypto_aead_chacha20poly1305_NPUBBYTES =
    sodium.crypto_aead_chacha20poly1305_NPUBBYTES;
  crypto_aead_chacha20poly1305_NSECBYTES =
    sodium.crypto_aead_chacha20poly1305_NSECBYTES;
  crypto_aead_chacha20poly1305_ietf_ABYTES =
    sodium.crypto_aead_chacha20poly1305_ietf_ABYTES;
  crypto_aead_chacha20poly1305_ietf_KEYBYTES =
    sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
  crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX =
    sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES =
    sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  crypto_aead_chacha20poly1305_ietf_NSECBYTES =
    sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES;
  crypto_aead_xchacha20poly1305_IETF_ABYTES =
    sodium.crypto_aead_xchacha20poly1305_IETF_ABYTES;
  crypto_aead_xchacha20poly1305_IETF_KEYBYTES =
    sodium.crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
  crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX =
    sodium.crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX;
  crypto_aead_xchacha20poly1305_IETF_NPUBBYTES =
    sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
  crypto_aead_xchacha20poly1305_IETF_NSECBYTES =
    sodium.crypto_aead_xchacha20poly1305_IETF_NSECBYTES;
  crypto_aead_xchacha20poly1305_ietf_ABYTES =
    sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
  crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX =
    sodium.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  crypto_aead_xchacha20poly1305_ietf_NSECBYTES =
    sodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
  crypto_auth_BYTES = sodium.crypto_auth_BYTES;
  crypto_auth_KEYBYTES = sodium.crypto_auth_KEYBYTES;
  crypto_box_BEFORENMBYTES = sodium.crypto_box_BEFORENMBYTES;
  crypto_box_MACBYTES = sodium.crypto_box_MACBYTES;
  crypto_box_MESSAGEBYTES_MAX = sodium.crypto_box_MESSAGEBYTES_MAX;
  crypto_box_NONCEBYTES = sodium.crypto_box_NONCEBYTES;
  crypto_box_PUBLICKEYBYTES = sodium.crypto_box_PUBLICKEYBYTES;
  crypto_box_SEALBYTES = sodium.crypto_box_SEALBYTES;
  crypto_box_SECRETKEYBYTES = sodium.crypto_box_SECRETKEYBYTES;
  crypto_box_SEEDBYTES = sodium.crypto_box_SEEDBYTES;
  crypto_generichash_BYTES = sodium.crypto_generichash_BYTES;
  crypto_generichash_BYTES_MAX = sodium.crypto_generichash_BYTES_MAX;
  crypto_generichash_BYTES_MIN = sodium.crypto_generichash_BYTES_MIN;
  crypto_generichash_KEYBYTES = sodium.crypto_generichash_KEYBYTES;
  crypto_generichash_KEYBYTES_MAX = sodium.crypto_generichash_KEYBYTES_MAX;
  crypto_generichash_KEYBYTES_MIN = sodium.crypto_generichash_KEYBYTES_MIN;
  crypto_hash_BYTES = sodium.crypto_hash_BYTES;
  crypto_kdf_BYTES_MAX = sodium.crypto_kdf_BYTES_MAX;
  crypto_kdf_BYTES_MIN = sodium.crypto_kdf_BYTES_MIN;
  crypto_kdf_CONTEXTBYTES = sodium.crypto_kdf_CONTEXTBYTES;
  crypto_kdf_KEYBYTES = sodium.crypto_kdf_KEYBYTES;
  crypto_kx_PUBLICKEYBYTES = sodium.crypto_kx_PUBLICKEYBYTES;
  crypto_kx_SECRETKEYBYTES = sodium.crypto_kx_SECRETKEYBYTES;
  crypto_kx_SEEDBYTES = sodium.crypto_kx_SEEDBYTES;
  crypto_kx_SESSIONKEYBYTES = sodium.crypto_kx_SESSIONKEYBYTES;
  crypto_pwhash_ALG_ARGON2I13 = sodium.crypto_pwhash_ALG_ARGON2I13;
  crypto_pwhash_ALG_ARGON2ID13 = sodium.crypto_pwhash_ALG_ARGON2ID13;
  crypto_pwhash_ALG_DEFAULT = sodium.crypto_pwhash_ALG_DEFAULT;
  crypto_pwhash_BYTES_MAX = sodium.crypto_pwhash_BYTES_MAX;
  crypto_pwhash_BYTES_MIN = sodium.crypto_pwhash_BYTES_MIN;
  crypto_pwhash_MEMLIMIT_INTERACTIVE =
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
  crypto_pwhash_MEMLIMIT_MAX = sodium.crypto_pwhash_MEMLIMIT_MAX;
  crypto_pwhash_MEMLIMIT_MIN = sodium.crypto_pwhash_MEMLIMIT_MIN;
  crypto_pwhash_MEMLIMIT_MODERATE = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  crypto_pwhash_MEMLIMIT_SENSITIVE = sodium.crypto_pwhash_MEMLIMIT_SENSITIVE;
  crypto_pwhash_OPSLIMIT_INTERACTIVE =
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  crypto_pwhash_OPSLIMIT_MAX = sodium.crypto_pwhash_OPSLIMIT_MAX;
  crypto_pwhash_OPSLIMIT_MIN = sodium.crypto_pwhash_OPSLIMIT_MIN;
  crypto_pwhash_OPSLIMIT_MODERATE = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  crypto_pwhash_OPSLIMIT_SENSITIVE = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE;
  crypto_pwhash_PASSWD_MAX = sodium.crypto_pwhash_PASSWD_MAX;
  crypto_pwhash_PASSWD_MIN = sodium.crypto_pwhash_PASSWD_MIN;
  crypto_pwhash_SALTBYTES = sodium.crypto_pwhash_SALTBYTES;
  crypto_pwhash_STRBYTES = sodium.crypto_pwhash_STRBYTES;
  crypto_scalarmult_BYTES = sodium.crypto_scalarmult_BYTES;
  crypto_scalarmult_SCALARBYTES = sodium.crypto_scalarmult_SCALARBYTES;
  crypto_secretbox_KEYBYTES = sodium.crypto_secretbox_KEYBYTES;
  crypto_secretbox_MACBYTES = sodium.crypto_secretbox_MACBYTES;
  crypto_secretbox_MESSAGEBYTES_MAX = sodium.crypto_secretbox_MESSAGEBYTES_MAX;
  crypto_secretbox_NONCEBYTES = sodium.crypto_secretbox_NONCEBYTES;
  crypto_secretstream_xchacha20poly1305_ABYTES =
    sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
  crypto_secretstream_xchacha20poly1305_HEADERBYTES =
    sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  crypto_secretstream_xchacha20poly1305_KEYBYTES =
    sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES;
  crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX =
    sodium.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;
  crypto_secretstream_xchacha20poly1305_TAG_FINAL =
    sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE =
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
  crypto_secretstream_xchacha20poly1305_TAG_PUSH =
    sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH;
  crypto_secretstream_xchacha20poly1305_TAG_REKEY =
    sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY;
  crypto_shorthash_BYTES = sodium.crypto_shorthash_BYTES;
  crypto_shorthash_KEYBYTES = sodium.crypto_shorthash_KEYBYTES;
  crypto_sign_BYTES = sodium.crypto_sign_BYTES;
  crypto_sign_MESSAGEBYTES_MAX = sodium.crypto_sign_MESSAGEBYTES_MAX;
  crypto_sign_PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES;
  crypto_sign_SECRETKEYBYTES = sodium.crypto_sign_SECRETKEYBYTES;
  crypto_sign_SEEDBYTES = sodium.crypto_sign_SEEDBYTES;
  SODIUM_VERSION_STRING = sodium.SODIUM_VERSION_STRING;
  crypto_pwhash_STRPREFIX = sodium.crypto_pwhash_STRPREFIX;
});

export let add = sodium.add;
export let base64_variants = sodium.base64_variants;
export let compare = sodium.compare;
export let from_base64 = sodium.from_base64;
export let from_hex = sodium.from_hex;
export let from_string = sodium.from_string;
export let increment = sodium.increment;
export let is_zero = sodium.is_zero;
// @ts-ignore
export let libsodium = sodium.libsodium;
export let memcmp = sodium.memcmp;
export let memzero = sodium.memzero;
export let output_formats = sodium.output_formats;
export let pad = sodium.pad;
export let unpad = sodium.unpad;
export let ready = sodium.ready;
export let symbols = sodium.symbols;
export let to_base64 = sodium.to_base64;
export let to_hex = sodium.to_hex;
export let to_string = sodium.to_string;
export let crypto_aead_chacha20poly1305_decrypt =
  sodium.crypto_aead_chacha20poly1305_decrypt;
export let crypto_aead_chacha20poly1305_decrypt_detached =
  sodium.crypto_aead_chacha20poly1305_decrypt_detached;
export let crypto_aead_chacha20poly1305_encrypt =
  sodium.crypto_aead_chacha20poly1305_encrypt;
export let crypto_aead_chacha20poly1305_encrypt_detached =
  sodium.crypto_aead_chacha20poly1305_encrypt_detached;
export let crypto_aead_chacha20poly1305_ietf_decrypt =
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt;
export let crypto_aead_chacha20poly1305_ietf_decrypt_detached =
  sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached;
export let crypto_aead_chacha20poly1305_ietf_encrypt =
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt;
export let crypto_aead_chacha20poly1305_ietf_encrypt_detached =
  sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached;
export let crypto_aead_chacha20poly1305_ietf_keygen =
  sodium.crypto_aead_chacha20poly1305_ietf_keygen;
export let crypto_aead_chacha20poly1305_keygen =
  sodium.crypto_aead_chacha20poly1305_keygen;
export let crypto_aead_xchacha20poly1305_ietf_decrypt =
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt;
export let crypto_aead_xchacha20poly1305_ietf_decrypt_detached =
  sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached;
export let crypto_aead_xchacha20poly1305_ietf_encrypt =
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt;
export let crypto_aead_xchacha20poly1305_ietf_encrypt_detached =
  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached;
export let crypto_aead_xchacha20poly1305_ietf_keygen =
  sodium.crypto_aead_xchacha20poly1305_ietf_keygen;
export let crypto_auth = sodium.crypto_auth;
export let crypto_auth_keygen = sodium.crypto_auth_keygen;
export let crypto_auth_verify = sodium.crypto_auth_verify;
export let crypto_box_beforenm = sodium.crypto_box_beforenm;
export let crypto_box_detached = sodium.crypto_box_detached;
export let crypto_box_easy = sodium.crypto_box_easy;
export let crypto_box_easy_afternm = sodium.crypto_box_easy_afternm;
export let crypto_box_keypair = sodium.crypto_box_keypair;
export let crypto_box_open_detached = sodium.crypto_box_open_detached;
export let crypto_box_open_easy = sodium.crypto_box_open_easy;
export let crypto_box_open_easy_afternm = sodium.crypto_box_open_easy_afternm;
export let crypto_box_seal = sodium.crypto_box_seal;
export let crypto_box_seal_open = sodium.crypto_box_seal_open;
export let crypto_box_seed_keypair = sodium.crypto_box_seed_keypair;
export let crypto_generichash = sodium.crypto_generichash;
export let crypto_generichash_final = sodium.crypto_generichash_final;
export let crypto_generichash_init = sodium.crypto_generichash_init;
export let crypto_generichash_keygen = sodium.crypto_generichash_keygen;
export let crypto_generichash_update = sodium.crypto_generichash_update;
export let crypto_hash = sodium.crypto_hash;
export let crypto_kdf_derive_from_key = sodium.crypto_kdf_derive_from_key;
export let crypto_kdf_keygen = sodium.crypto_kdf_keygen;
export let crypto_kx_client_session_keys = sodium.crypto_kx_client_session_keys;
export let crypto_kx_keypair = sodium.crypto_kx_keypair;
export let crypto_kx_seed_keypair = sodium.crypto_kx_seed_keypair;
export let crypto_kx_server_session_keys = sodium.crypto_kx_server_session_keys;
export let crypto_pwhash = sodium.crypto_pwhash;
export let crypto_pwhash_str = sodium.crypto_pwhash_str;
export let crypto_pwhash_str_needs_rehash =
  sodium.crypto_pwhash_str_needs_rehash;
export let crypto_pwhash_str_verify = sodium.crypto_pwhash_str_verify;
export let crypto_scalarmult = sodium.crypto_scalarmult;
export let crypto_scalarmult_base = sodium.crypto_scalarmult_base;
export let crypto_secretbox_detached = sodium.crypto_secretbox_detached;
export let crypto_secretbox_easy = sodium.crypto_secretbox_easy;
export let crypto_secretbox_keygen = sodium.crypto_secretbox_keygen;
export let crypto_secretbox_open_detached =
  sodium.crypto_secretbox_open_detached;
export let crypto_secretbox_open_easy = sodium.crypto_secretbox_open_easy;
export let crypto_secretstream_xchacha20poly1305_init_pull =
  sodium.crypto_secretstream_xchacha20poly1305_init_pull;
export let crypto_secretstream_xchacha20poly1305_init_push =
  sodium.crypto_secretstream_xchacha20poly1305_init_push;
export let crypto_secretstream_xchacha20poly1305_keygen =
  sodium.crypto_secretstream_xchacha20poly1305_keygen;
export let crypto_secretstream_xchacha20poly1305_pull =
  sodium.crypto_secretstream_xchacha20poly1305_pull;
export let crypto_secretstream_xchacha20poly1305_push =
  sodium.crypto_secretstream_xchacha20poly1305_push;
export let crypto_secretstream_xchacha20poly1305_rekey =
  sodium.crypto_secretstream_xchacha20poly1305_rekey;
export let crypto_shorthash = sodium.crypto_shorthash;
export let crypto_shorthash_keygen = sodium.crypto_shorthash_keygen;
export let crypto_sign = sodium.crypto_sign;
export let crypto_sign_detached = sodium.crypto_sign_detached;
export let crypto_sign_ed25519_pk_to_curve25519 =
  sodium.crypto_sign_ed25519_pk_to_curve25519;
export let crypto_sign_ed25519_sk_to_curve25519 =
  sodium.crypto_sign_ed25519_sk_to_curve25519;
export let crypto_sign_final_create = sodium.crypto_sign_final_create;
export let crypto_sign_final_verify = sodium.crypto_sign_final_verify;
export let crypto_sign_init = sodium.crypto_sign_init;
export let crypto_sign_keypair = sodium.crypto_sign_keypair;
export let crypto_sign_open = sodium.crypto_sign_open;
export let crypto_sign_seed_keypair = sodium.crypto_sign_seed_keypair;
export let crypto_sign_update = sodium.crypto_sign_update;
export let crypto_sign_verify_detached = sodium.crypto_sign_verify_detached;
export let randombytes_buf = sodium.randombytes_buf;
export let randombytes_buf_deterministic = sodium.randombytes_buf_deterministic;
export let randombytes_close = sodium.randombytes_close;
export let randombytes_random = sodium.randombytes_random;
export let randombytes_stir = sodium.randombytes_stir;
export let randombytes_uniform = sodium.randombytes_uniform;
export let sodium_version_string = sodium.sodium_version_string;
export let SODIUM_LIBRARY_VERSION_MAJOR = sodium.SODIUM_LIBRARY_VERSION_MAJOR;
export let SODIUM_LIBRARY_VERSION_MINOR = sodium.SODIUM_LIBRARY_VERSION_MINOR;
export let crypto_aead_chacha20poly1305_ABYTES =
  sodium.crypto_aead_chacha20poly1305_ABYTES;
export let crypto_aead_chacha20poly1305_IETF_ABYTES =
  sodium.crypto_aead_chacha20poly1305_IETF_ABYTES;
export let crypto_aead_chacha20poly1305_IETF_KEYBYTES =
  sodium.crypto_aead_chacha20poly1305_IETF_KEYBYTES;
export let crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX =
  sodium.crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX;
export let crypto_aead_chacha20poly1305_IETF_NPUBBYTES =
  sodium.crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
export let crypto_aead_chacha20poly1305_IETF_NSECBYTES =
  sodium.crypto_aead_chacha20poly1305_IETF_NSECBYTES;
export let crypto_aead_chacha20poly1305_KEYBYTES =
  sodium.crypto_aead_chacha20poly1305_KEYBYTES;
export let crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX =
  sodium.crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX;
export let crypto_aead_chacha20poly1305_NPUBBYTES =
  sodium.crypto_aead_chacha20poly1305_NPUBBYTES;
export let crypto_aead_chacha20poly1305_NSECBYTES =
  sodium.crypto_aead_chacha20poly1305_NSECBYTES;
export let crypto_aead_chacha20poly1305_ietf_ABYTES =
  sodium.crypto_aead_chacha20poly1305_ietf_ABYTES;
export let crypto_aead_chacha20poly1305_ietf_KEYBYTES =
  sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
export let crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX =
  sodium.crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX;
export let crypto_aead_chacha20poly1305_ietf_NPUBBYTES =
  sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
export let crypto_aead_chacha20poly1305_ietf_NSECBYTES =
  sodium.crypto_aead_chacha20poly1305_ietf_NSECBYTES;
export let crypto_aead_xchacha20poly1305_IETF_ABYTES =
  sodium.crypto_aead_xchacha20poly1305_IETF_ABYTES;
export let crypto_aead_xchacha20poly1305_IETF_KEYBYTES =
  sodium.crypto_aead_xchacha20poly1305_IETF_KEYBYTES;
export let crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX =
  sodium.crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX;
export let crypto_aead_xchacha20poly1305_IETF_NPUBBYTES =
  sodium.crypto_aead_xchacha20poly1305_IETF_NPUBBYTES;
export let crypto_aead_xchacha20poly1305_IETF_NSECBYTES =
  sodium.crypto_aead_xchacha20poly1305_IETF_NSECBYTES;
export let crypto_aead_xchacha20poly1305_ietf_ABYTES =
  sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;
export let crypto_aead_xchacha20poly1305_ietf_KEYBYTES =
  sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
export let crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX =
  sodium.crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
export let crypto_aead_xchacha20poly1305_ietf_NPUBBYTES =
  sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
export let crypto_aead_xchacha20poly1305_ietf_NSECBYTES =
  sodium.crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
export let crypto_auth_BYTES = sodium.crypto_auth_BYTES;
export let crypto_auth_KEYBYTES = sodium.crypto_auth_KEYBYTES;
export let crypto_box_BEFORENMBYTES = sodium.crypto_box_BEFORENMBYTES;
export let crypto_box_MACBYTES = sodium.crypto_box_MACBYTES;
export let crypto_box_MESSAGEBYTES_MAX = sodium.crypto_box_MESSAGEBYTES_MAX;
export let crypto_box_NONCEBYTES = sodium.crypto_box_NONCEBYTES;
export let crypto_box_PUBLICKEYBYTES = sodium.crypto_box_PUBLICKEYBYTES;
export let crypto_box_SEALBYTES = sodium.crypto_box_SEALBYTES;
export let crypto_box_SECRETKEYBYTES = sodium.crypto_box_SECRETKEYBYTES;
export let crypto_box_SEEDBYTES = sodium.crypto_box_SEEDBYTES;
export let crypto_generichash_BYTES = sodium.crypto_generichash_BYTES;
export let crypto_generichash_BYTES_MAX = sodium.crypto_generichash_BYTES_MAX;
export let crypto_generichash_BYTES_MIN = sodium.crypto_generichash_BYTES_MIN;
export let crypto_generichash_KEYBYTES = sodium.crypto_generichash_KEYBYTES;
export let crypto_generichash_KEYBYTES_MAX =
  sodium.crypto_generichash_KEYBYTES_MAX;
export let crypto_generichash_KEYBYTES_MIN =
  sodium.crypto_generichash_KEYBYTES_MIN;
export let crypto_hash_BYTES = sodium.crypto_hash_BYTES;
export let crypto_kdf_BYTES_MAX = sodium.crypto_kdf_BYTES_MAX;
export let crypto_kdf_BYTES_MIN = sodium.crypto_kdf_BYTES_MIN;
export let crypto_kdf_CONTEXTBYTES = sodium.crypto_kdf_CONTEXTBYTES;
export let crypto_kdf_KEYBYTES = sodium.crypto_kdf_KEYBYTES;
export let crypto_kx_PUBLICKEYBYTES = sodium.crypto_kx_PUBLICKEYBYTES;
export let crypto_kx_SECRETKEYBYTES = sodium.crypto_kx_SECRETKEYBYTES;
export let crypto_kx_SEEDBYTES = sodium.crypto_kx_SEEDBYTES;
export let crypto_kx_SESSIONKEYBYTES = sodium.crypto_kx_SESSIONKEYBYTES;
export let crypto_pwhash_ALG_ARGON2I13 = sodium.crypto_pwhash_ALG_ARGON2I13;
export let crypto_pwhash_ALG_ARGON2ID13 = sodium.crypto_pwhash_ALG_ARGON2ID13;
export let crypto_pwhash_ALG_DEFAULT = sodium.crypto_pwhash_ALG_DEFAULT;
export let crypto_pwhash_BYTES_MAX = sodium.crypto_pwhash_BYTES_MAX;
export let crypto_pwhash_BYTES_MIN = sodium.crypto_pwhash_BYTES_MIN;
export let crypto_pwhash_MEMLIMIT_INTERACTIVE =
  sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
export let crypto_pwhash_MEMLIMIT_MAX = sodium.crypto_pwhash_MEMLIMIT_MAX;
export let crypto_pwhash_MEMLIMIT_MIN = sodium.crypto_pwhash_MEMLIMIT_MIN;
export let crypto_pwhash_MEMLIMIT_MODERATE =
  sodium.crypto_pwhash_MEMLIMIT_MODERATE;
export let crypto_pwhash_MEMLIMIT_SENSITIVE =
  sodium.crypto_pwhash_MEMLIMIT_SENSITIVE;
export let crypto_pwhash_OPSLIMIT_INTERACTIVE =
  sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
export let crypto_pwhash_OPSLIMIT_MAX = sodium.crypto_pwhash_OPSLIMIT_MAX;
export let crypto_pwhash_OPSLIMIT_MIN = sodium.crypto_pwhash_OPSLIMIT_MIN;
export let crypto_pwhash_OPSLIMIT_MODERATE =
  sodium.crypto_pwhash_OPSLIMIT_MODERATE;
export let crypto_pwhash_OPSLIMIT_SENSITIVE =
  sodium.crypto_pwhash_OPSLIMIT_SENSITIVE;
export let crypto_pwhash_PASSWD_MAX = sodium.crypto_pwhash_PASSWD_MAX;
export let crypto_pwhash_PASSWD_MIN = sodium.crypto_pwhash_PASSWD_MIN;
export let crypto_pwhash_SALTBYTES = sodium.crypto_pwhash_SALTBYTES;
export let crypto_pwhash_STRBYTES = sodium.crypto_pwhash_STRBYTES;
export let crypto_scalarmult_BYTES = sodium.crypto_scalarmult_BYTES;
export let crypto_scalarmult_SCALARBYTES = sodium.crypto_scalarmult_SCALARBYTES;
export let crypto_secretbox_KEYBYTES = sodium.crypto_secretbox_KEYBYTES;
export let crypto_secretbox_MACBYTES = sodium.crypto_secretbox_MACBYTES;
export let crypto_secretbox_MESSAGEBYTES_MAX =
  sodium.crypto_secretbox_MESSAGEBYTES_MAX;
export let crypto_secretbox_NONCEBYTES = sodium.crypto_secretbox_NONCEBYTES;
export let crypto_secretstream_xchacha20poly1305_ABYTES =
  sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
export let crypto_secretstream_xchacha20poly1305_HEADERBYTES =
  sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
export let crypto_secretstream_xchacha20poly1305_KEYBYTES =
  sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES;
export let crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX =
  sodium.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;
export let crypto_secretstream_xchacha20poly1305_TAG_FINAL =
  sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
export let crypto_secretstream_xchacha20poly1305_TAG_MESSAGE =
  sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
export let crypto_secretstream_xchacha20poly1305_TAG_PUSH =
  sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH;
export let crypto_secretstream_xchacha20poly1305_TAG_REKEY =
  sodium.crypto_secretstream_xchacha20poly1305_TAG_REKEY;
export let crypto_shorthash_BYTES = sodium.crypto_shorthash_BYTES;
export let crypto_shorthash_KEYBYTES = sodium.crypto_shorthash_KEYBYTES;
export let crypto_sign_BYTES = sodium.crypto_sign_BYTES;
export let crypto_sign_MESSAGEBYTES_MAX = sodium.crypto_sign_MESSAGEBYTES_MAX;
export let crypto_sign_PUBLICKEYBYTES = sodium.crypto_sign_PUBLICKEYBYTES;
export let crypto_sign_SECRETKEYBYTES = sodium.crypto_sign_SECRETKEYBYTES;
export let crypto_sign_SEEDBYTES = sodium.crypto_sign_SEEDBYTES;
export let SODIUM_VERSION_STRING = sodium.SODIUM_VERSION_STRING;
export let crypto_pwhash_STRPREFIX = sodium.crypto_pwhash_STRPREFIX;
