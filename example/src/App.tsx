import * as React from 'react';

import { StyleSheet, Text, View } from 'react-native';
import {
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_keygen,
  from_base64,
  to_base64,
  to_string,
} from 'react-native-rnlibsodium';

export default function App() {
  const resultBase64 = to_base64('Hello World');
  const resultUint8Array = from_base64(resultBase64);
  const result2Base64 = to_base64(resultUint8Array);
  const resultString = to_string(resultUint8Array);
  console.log({ resultBase64, resultUint8Array, result2Base64, resultString });
  const secretBoxKey = crypto_secretbox_keygen();
  console.log({ secretBoxKey });
  console.log({ crypto_secretbox_KEYBYTES });

  return (
    <View style={styles.container}>
      <Text>{to_base64('wow')}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});
