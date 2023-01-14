import React from 'react';
import { Text } from 'react-native';
import { to_base64, crypto_box_easy } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
  nonce: Uint8Array;
  senderPrivateKey: Uint8Array;
  receiverPublicKey: Uint8Array;
};

export const Test_crypto_box_easy: React.FC<Props> = ({
  message,
  nonce,
  senderPrivateKey,
  receiverPublicKey,
}) => {
  const ciphertext = crypto_box_easy(
    message,
    nonce,
    senderPrivateKey,
    receiverPublicKey
  );

  return (
    <>
      <FunctionStatus name="crypto_box_easy" success={true}>
        <Text>{to_base64(ciphertext)}</Text>
      </FunctionStatus>
    </>
  );
};
