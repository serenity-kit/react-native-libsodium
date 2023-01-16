import React from 'react';
import { crypto_aead_xchacha20poly1305_ietf_decrypt } from 'react-native-libsodium';
import { FunctionStatus } from '../FunctionStatus';
import { isStringUtf8ArrayEquivalent } from '../../utils/isStringUtf8ArrayEquivalent';

type Props = {
  secretNonce: null;
  ciphertext: Uint8Array;
  additionalData: string;
  publicNonce: Uint8Array;
  symmetricKey: Uint8Array;
  message: string | Uint8Array;
};

export const Test_crypto_aead_xchacha20poly1305_ietf_decrypt: React.FC<
  Props
> = ({
  secretNonce,
  ciphertext,
  additionalData,
  publicNonce,
  symmetricKey,
  message,
}) => {
  const decryptedMessage = crypto_aead_xchacha20poly1305_ietf_decrypt(
    secretNonce,
    ciphertext,
    additionalData,
    publicNonce,
    symmetricKey
  );

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_decrypt"
        success={isStringUtf8ArrayEquivalent(decryptedMessage, message)}
        output={decryptedMessage}
        inputs={{
          secretNonce,
          ciphertext,
          additionalData,
          publicNonce,
          key: symmetricKey,
        }}
      />
    </>
  );
};
