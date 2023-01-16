import React from 'react';
import { StyleSheet, View, Text } from 'react-native';
import { getType } from '../../utils/getType';
import { FunctionStatus } from '../FunctionStatus';
import { Header } from '../Header';
import {
  to_base64,
  crypto_sign_keypair,
  crypto_sign_detached,
} from 'react-native-libsodium';
import { Test_crypto_sign_verify_detached } from '../tests/Test_crypto_sign_verify_detached';

const message = 'Hello World';

export const Test_crypto_signing: React.FC = () => {
  const keyPair = crypto_sign_keypair();
  const signature = crypto_sign_detached(message, keyPair.privateKey);

  return (
    <>
      <Header>Signing</Header>
      <FunctionStatus
        name="crypto_sign_keypair"
        success={keyPair.keyType === 'ed25519'}
      >
        <View style={styles.children}>
          <View style={styles.output}>
            <Text style={styles.outputType}>⬅ (object)</Text>
          </View>
          <View style={styles.output}>
            <Text style={styles.partialOutputType}>
              {getType(keyPair.privateKey)}
            </Text>
            <Text>.privateKey: {to_base64(keyPair.privateKey)}</Text>
          </View>
          <View style={styles.output}>
            <Text style={styles.partialOutputType}>
              {getType(keyPair.publicKey)}
            </Text>
            <Text>.publicKey: {to_base64(keyPair.publicKey)}</Text>
          </View>
          <View style={styles.output}>
            <Text style={styles.partialOutputType}>
              {getType(keyPair.keyType)}
            </Text>
            <Text>.keyType: {keyPair.keyType}</Text>
          </View>
        </View>
      </FunctionStatus>
      <FunctionStatus
        name="crypto_sign_detached"
        success={true}
        output={signature}
        inputs={{
          message,
          privateKey: keyPair.privateKey,
        }}
      />
      <Test_crypto_sign_verify_detached
        signature={signature}
        message={message}
        publicKey={keyPair.publicKey}
      />
    </>
  );
};

const styles = StyleSheet.create({
  container: {
    borderColor: 'black',
    borderBottomWidth: 1,
    width: '100%',
  },
  result: {
    display: 'flex',
    flexDirection: 'row',
    paddingVertical: 10,
    paddingHorizontal: 5,
  },
  children: {
    paddingTop: 5,
    backgroundColor: '#eee',
    paddingVertical: 10,
    paddingHorizontal: 5,
  },
  outputType: {
    color: '#666',
    marginRight: 10,
    marginBottom: 10,
  },
  partialOutputType: {
    color: '#666',
    marginRight: 10,
    marginLeft: 10,
  },
  output: {
    flexDirection: 'row',
  },
});
