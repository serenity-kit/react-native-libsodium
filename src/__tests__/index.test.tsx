describe('package', () => {
  it('should export implemented functions', () => {
    const knownExports = [
      'crypto_auth',
      'crypto_auth_verify',
      'crypto_auth_BYTES',
      'crypto_auth_KEYBYTES',
      'crypto_auth_keygen',
      'crypto_aead_xchacha20poly1305_ietf_decrypt',
      'crypto_aead_xchacha20poly1305_ietf_encrypt',
      'crypto_aead_xchacha20poly1305_ietf_KEYBYTES',
      'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES',
      'crypto_aead_xchacha20poly1305_ietf_keygen',
      'crypto_box_easy',
      'crypto_box_keypair',
      'crypto_box_seed_keypair',
      'crypto_box_open_easy',
      'crypto_box_PUBLICKEYBYTES',
      'crypto_box_SECRETKEYBYTES',
      'crypto_box_SEEDBYTES',
      'crypto_box_seal',
      'crypto_box_seal_open',
      'crypto_kdf_CONTEXTBYTES',
      'crypto_kdf_derive_from_key',
      'crypto_kdf_KEYBYTES',
      'crypto_kdf_keygen',
      'crypto_pwhash',
      'crypto_pwhash_ALG_DEFAULT',
      'crypto_pwhash_MEMLIMIT_INTERACTIVE',
      'crypto_pwhash_OPSLIMIT_INTERACTIVE',
      'crypto_pwhash_SALTBYTES',
      'crypto_generichash',
      'crypto_generichash_BYTES',
      'crypto_generichash_BYTES_MIN',
      'crypto_generichash_BYTES_MAX',
      'crypto_generichash_KEYBYTES',
      'crypto_generichash_KEYBYTES_MIN',
      'crypto_generichash_KEYBYTES_MAX',
      'crypto_secretbox_easy',
      'crypto_secretbox_KEYBYTES',
      'crypto_secretbox_keygen',
      'crypto_secretbox_NONCEBYTES',
      'crypto_secretbox_open_easy',
      'crypto_sign_detached',
      'crypto_sign_keypair',
      'crypto_sign_SEEDBYTES',
      'crypto_sign_verify_detached',
      'from_base64',
      'from_hex',
      'randombytes_buf',
      'randombytes_uniform',
      'to_base64',
      'to_hex',
      'to_string',
      'ready',
      'loadSumoVersion',
      '_unstable_crypto_kdf_hkdf_sha256_BYTES_MAX',
      '_unstable_crypto_kdf_hkdf_sha256_BYTES_MIN',
      '_unstable_crypto_kdf_hkdf_sha256_KEYBYTES',
      '_unstable_crypto_kdf_hkdf_sha256_extract',
      '_unstable_crypto_kdf_hkdf_sha256_expand',
    ];
    const pkg = require('../index');
    knownExports.forEach((exported) => {
      expect(pkg).toHaveProperty(exported);
    });
  });

  it('should throw on non-implemented functions', () => {
    const knownNotImplemented = ['crypto_scalarmult', 'memcmp', 'memzero'];
    const pkg = require('../index');
    knownNotImplemented.forEach((notImplemented) => {
      expect(pkg).not.toHaveProperty(notImplemented);
    });
  });
});
