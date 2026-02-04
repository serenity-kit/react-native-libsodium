import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
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
import '../tests/crypto_box_keypair_test';
import '../tests/crypto_box_open_easy_test';
import '../tests/crypto_box_seal_test';
import '../tests/crypto_box_seed_keypair_test';
import '../tests/crypto_generichash_test';
import '../tests/crypto_kdf_derive_from_key_test';
import '../tests/crypto_kdf_keygen_test';
import '../tests/crypto_pwhash_test';
import '../tests/crypto_sign_ed25519_pk_to_curve25519_test';
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
    <View style={styles.container}>
      {allTestsPassed != null && (
        <Text style={styles.statusText}>
          {allTestsPassed ? 'Tests passed' : 'Tests failed'}
        </Text>
      )}
      {testResults &&
        testResults.map((result) => {
          const title = result.descriptions
            .concat(result.test.description)
            .join(' / ');
          return (
            <View key={result.test.id} style={styles.resultContainer}>
              <View style={styles.row}>
                <Text>{!result.success ? '❌' : '✅'}</Text>
                <Text style={styles.title}>{title}</Text>
              </View>
              {!result.success && (
                <Text style={styles.errorText}>{'' + result.error}</Text>
              )}
              {(() => {
                if (
                  result.success ||
                  typeof result.error !== 'object' ||
                  !result.error ||
                  !('stack' in result.error)
                ) {
                  return null;
                }
                const stack = (result.error as { stack?: unknown }).stack;
                return stack != null ? (
                  <View style={styles.stackContainer}>
                    <Text style={styles.stackText}>{String(stack)}</Text>
                  </View>
                ) : null;
              })()}
            </View>
          );
        })}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flexDirection: 'column',
    gap: 8,
    padding: 16,
  },
  statusText: {
    fontSize: 20,
  },
  resultContainer: {
    gap: 8,
  },
  row: {
    flexDirection: 'row',
    gap: 8,
  },
  title: {
    fontSize: 16,
  },
  errorText: {
    color: 'red',
    fontSize: 16,
  },
  stackContainer: {
    backgroundColor: '#ddd',
    padding: 16,
  },
  stackText: {
    fontFamily: 'monospace',
  },
});
