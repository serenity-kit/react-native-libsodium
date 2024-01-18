import React, { useEffect, useState } from 'react';
import { Text, View } from 'react-native';
import '../tests/_unstable_crypto_kdf_hkdf_sha256_expand_test';
import '../tests/_unstable_crypto_kdf_hkdf_sha256_extract_test';
import '../tests/constants_test';
import '../tests/crypto_aead_xchacha20poly1305_ietf_decrypt_test';
import '../tests/crypto_aead_xchacha20poly1305_ietf_encrypt_test';
import '../tests/crypto_aead_xchacha20poly1305_ietf_keygen_test';
import '../tests/crypto_auth_keygen_test';
import '../tests/crypto_auth_test';
import '../tests/crypto_auth_verify_test';
import '../tests/crypto_box_easy_test';
import '../tests/crypto_box_seal_test';
import '../tests/crypto_box_keypair_test';
import '../tests/crypto_box_open_easy_test';
import '../tests/crypto_generichash_test';
import '../tests/crypto_kdf_derive_from_key_test';
import '../tests/crypto_kdf_keygen_test';
import '../tests/crypto_pwhash_test';
import '../tests/crypto_secretbox_easy_test';
import '../tests/crypto_secretbox_keygen_test';
import '../tests/crypto_secretbox_open_easy_test';
import '../tests/crypto_sign_detached_test';
import '../tests/crypto_sign_keypair_test';
import '../tests/crypto_sign_seed_keypair_test';
import '../tests/crypto_sign_verify_detached_test';
import '../tests/from_base64_test';
import '../tests/randombytes_buf_test';
import '../tests/randombytes_uniform_test';
import '../tests/to_base64_test';
import '../tests/to_hex_test';
import { TestResult, runTests } from '../utils/testRunner';

export const TestResults: React.FC = () => {
  const [testResults, setTestResults] = useState<TestResult[] | null>(null);

  const allTestsPassed =
    testResults && !testResults.some((testEntry) => !testEntry.success);

  useEffect(() => {
    runTests().then((results) => {
      if (results.some((t) => !t.success)) {
        console.error(results);
      }
      setTestResults(results);
    });
  }, []);

  return (
    <View style={{ flexDirection: 'column', gap: 8, padding: 16 }}>
      {allTestsPassed != null && (
        <Text style={{ fontSize: 20 }}>
          {allTestsPassed ? 'Tests passed' : 'Tests failed'}
        </Text>
      )}
      {testResults &&
        testResults.map((result) => {
          const title = result.descriptions
            .concat(result.test.description)
            .join(' / ');
          return (
            <View key={result.test.id} style={{ gap: 8 }}>
              <View style={{ flexDirection: 'row', gap: 8 }}>
                <Text>{!result.success ? '❌' : '✅'}</Text>
                <Text style={{ fontSize: 16 }}>{title}</Text>
              </View>
              {!result.success && (
                <Text style={{ fontSize: 16, color: 'red' }}>
                  {'' + result.error}
                </Text>
              )}
              {!result.success &&
                typeof result.error === 'object' &&
                result.error &&
                'stack' in result.error && (
                  <View style={{ backgroundColor: '#ddd', padding: 16 }}>
                    <Text style={{ fontFamily: 'monospace' }}>
                      {result.error.stack}
                    </Text>
                  </View>
                )}
            </View>
          );
        })}
    </View>
  );
};
