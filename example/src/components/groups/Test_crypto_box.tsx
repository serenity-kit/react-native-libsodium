import React from 'react';
import { StyleSheet, View, Text } from 'react-native';
import { getType } from '../../utils/getType';
import { FunctionStatus } from '../FunctionStatus';
import { Header } from '../Header';
import {
  to_base64,
  randombytes_buf,
  crypto_box_NONCEBYTES,
  crypto_box_keypair,
  crypto_box_easy,
} from 'react-native-libsodium';
import { Test_crypto_box_open_easy } from '../tests/Test_crypto_box_open_easy';

type Props = {
  message: string | Uint8Array;
};

export const Test_crypto_box: React.FC<Props> = ({ message }) => {
  const senderKeyPair = crypto_box_keypair();
  const receiverKeyPair = crypto_box_keypair();
  const nonce = randombytes_buf(crypto_box_NONCEBYTES);
  const ciphertext = crypto_box_easy(
    message,
    nonce,
    receiverKeyPair.publicKey,
    senderKeyPair.privateKey
  );

  return (
    <>
      <Header>Box Encryption (Asymmetric Key)</Header>
      <FunctionStatus
        name="crypto_box_keypair"
        success={senderKeyPair.keyType === 'curve25519'}
      >
        <View style={styles.children}>
          <View style={styles.output}>
            <Text style={styles.outputType}>⬅ (object)</Text>
          </View>
          <View style={styles.output}>
            <Text style={styles.partialOutputType}>
              {getType(senderKeyPair.privateKey)}
            </Text>
            <Text>.privateKey: {to_base64(senderKeyPair.privateKey)}</Text>
          </View>
          <View style={styles.output}>
            <Text style={styles.partialOutputType}>
              {getType(senderKeyPair.publicKey)}
            </Text>
            <Text>.publicKey: {to_base64(senderKeyPair.publicKey)}</Text>
          </View>
          <View style={styles.output}>
            <Text style={styles.partialOutputType}>
              {getType(senderKeyPair.keyType)}
            </Text>
            <Text>.keyType: {senderKeyPair.keyType}</Text>
          </View>
        </View>
      </FunctionStatus>
      <FunctionStatus
        name="crypto_box_easy"
        success={true}
        output={ciphertext}
        inputs={{
          message,
          nonce,
          privateKey: senderKeyPair.privateKey,
          publicKey: receiverKeyPair.publicKey,
        }}
      />
      <Test_crypto_box_open_easy
        ciphertext={ciphertext}
        nonce={nonce}
        senderPublicKey={senderKeyPair.publicKey}
        receiverPrivateKey={receiverKeyPair.privateKey}
        message={message}
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
