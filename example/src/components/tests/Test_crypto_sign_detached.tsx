import React from 'react';
import {
  crypto_sign_detached,
  crypto_sign_keypair,
  crypto_sign_verify_detached,
} from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';

type Props = {
  message: string | Uint8Array;
};

export const Test_crypto_sign_detached: React.FC<Props> = ({ message }) => {
  const keyPair = crypto_sign_keypair();
  const signature = crypto_sign_detached(message, keyPair.privateKey);
  const signatureVerifies = crypto_sign_verify_detached(
    signature,
    message,
    keyPair.publicKey
  );

  return (
    <>
      <FunctionStatus
        name="crypto_sign_detached"
        success={signature.length === 64 && signatureVerifies === true}
      />
    </>
  );
};
