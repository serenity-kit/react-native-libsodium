import * as React from 'react';

import { StyleSheet, Text, View } from 'react-native';
import { from_base64, multiply, to_base64 } from 'react-native-rnlibsodium';

export default function App() {
  return (
    <View style={styles.container}>
      <Text>
        Result: {multiply()} {to_base64('wow', 1)}
        {from_base64(to_base64('wow', 1), 1)}
      </Text>
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
