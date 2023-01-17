import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import {
  crypto_box_keypair,
  crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES,
  from_base64,
  to_base64,
} from 'react-native-libsodium';
import { getType } from '../../utils/getType';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  outputFormat?: any;
};

export const Test_crypto_box_keypair: React.FC<Props> = ({ outputFormat }) => {
  const keyPair = crypto_box_keypair(outputFormat);

  const lengthVerifies = (key: any, expectedLength: number) => {
    const keyLength = key.length;
    if (outputFormat === 'base64') {
      return (
        typeof key === 'string' && from_base64(key).length === expectedLength
      );
    } else if (outputFormat === 'hex') {
      return typeof key === 'string' && keyLength === expectedLength * 2;
    } else {
      return typeof key === 'object' && keyLength === expectedLength;
    }
  };

  const verifies = () => {
    return (
      keyPair.keyType === 'curve25519' &&
      lengthVerifies(keyPair.publicKey, crypto_box_PUBLICKEYBYTES) &&
      lengthVerifies(keyPair.privateKey, crypto_box_SECRETKEYBYTES)
    );
  };

  return (
    <>
      <FunctionStatus name="crypto_box_keypair" success={verifies()}>
        <View style={styles.children}>
          <View style={styles.output}>
            <Text style={styles.outputType}>(object)</Text>
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
