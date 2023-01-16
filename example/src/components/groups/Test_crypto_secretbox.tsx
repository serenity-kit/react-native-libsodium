import React from 'react';
import { FunctionStatus } from '../FunctionStatus';
import { Header } from '../Header';
import {
  randombytes_buf,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_keygen,
  crypto_secretbox_easy,
} from 'react-native-libsodium';
import { Test_crypto_secretbox_open_easy } from '../tests/Test_crypto_secretbox_open_easy';
import { Test_crypto_secretbox_keygen } from '../tests/Test_crypto_secretbox_keygen';

type Props = {
  message: string | Uint8Array;
};

export const Test_crypto_secretbox: React.FC<Props> = ({ message }) => {
  const key = crypto_secretbox_keygen();
  const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES);
  const ciphertext = crypto_secretbox_easy(message, nonce, key);

  return (
    <>
      <Header>Secret Encryption (Symmetric Key)</Header>
      <Test_crypto_secretbox_keygen />
      <Test_crypto_secretbox_keygen outputFormat={'base64'} />
      <Test_crypto_secretbox_keygen outputFormat={'hex'} />
      <FunctionStatus name="crypto_box_keypair" success={true} output={key} />
      <FunctionStatus
        name="crypto_secretbox_easy"
        success={true}
        output={ciphertext}
        inputs={{
          message,
          nonce,
          key,
        }}
      />
      <Test_crypto_secretbox_open_easy
        ciphertext={ciphertext}
        nonce={nonce}
        symmetricKey={key}
        message={message}
      />
    </>
  );
};
