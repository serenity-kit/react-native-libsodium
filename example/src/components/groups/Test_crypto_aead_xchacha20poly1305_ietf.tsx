import React from 'react';
import { FunctionStatus } from '../FunctionStatus';
import { Header } from '../Header';
import {
  randombytes_buf,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
} from 'react-native-libsodium';
import { Test_crypto_aead_xchacha20poly1305_ietf_decrypt } from '../tests/Test_crypto_aead_xchacha20poly1305_ietf_decrypt';
import { Test_crypto_aead_xchacha20poly1305_ietf_keygen } from '../tests/Test_crypto_aead_xchacha20poly1305_ietf_keygen';

type Props = {
  message: string | Uint8Array;
  additionalData: string;
};

export const Test_crypto_aead_xchacha20poly1305_ietf: React.FC<Props> = ({
  message,
  additionalData,
}) => {
  const key = crypto_aead_xchacha20poly1305_ietf_keygen();
  const secretNonce = null;
  const publicNonce = randombytes_buf(
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    additionalData,
    secretNonce,
    publicNonce,
    key
  );
  return (
    <>
      <Header>AEAD Encryption (Symmetric Key)</Header>
      <Test_crypto_aead_xchacha20poly1305_ietf_keygen />
      <Test_crypto_aead_xchacha20poly1305_ietf_keygen outputFormat={'base64'} />
      <Test_crypto_aead_xchacha20poly1305_ietf_keygen outputFormat={'hex'} />
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_keygen"
        success={true}
        output={key}
      />
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_encrypt"
        success={true}
        output={ciphertext}
        inputs={{
          message,
          additionalData,
          secretNonce,
          publicNonce,
          key,
        }}
      />
      <Test_crypto_aead_xchacha20poly1305_ietf_decrypt
        ciphertext={ciphertext}
        additionalData={additionalData}
        secretNonce={secretNonce}
        publicNonce={publicNonce}
        symmetricKey={key}
        message={message}
      />
    </>
  );
};
