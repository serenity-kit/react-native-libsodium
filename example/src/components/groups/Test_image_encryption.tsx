import React from 'react';
import {
  randombytes_buf,
  crypto_aead_xchacha20poly1305_ietf_keygen,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
} from 'react-native-libsodium';
import { Image } from 'react-native';
import { FunctionStatus } from '../FunctionStatus';
import { Header } from '../Header';
import { encryptAndDecryptImage } from '../../utils/encryptAndDecryptImage';
import { Test_crypto_aead_xchacha20poly1305_ietf_decrypt } from '../tests/Test_crypto_aead_xchacha20poly1305_ietf_decrypt';
import { largeContent } from '../../largeContent';
import { threeMbImage } from '../../threeMbImage';

type Props = {
  message: string;
  additionalData: string;
  variant: string;
};

export const Test_image_encryption: React.FC<Props> = ({
  message,
  additionalData,
  variant,
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
  const decryptedImage = encryptAndDecryptImage(largeContent);
  const decryptedImageThreeMb = encryptAndDecryptImage(threeMbImage);

  return (
    <>
      <Header>Image Encryption ({variant})</Header>
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
      <Image
        style={{ width: 120, height: 100 }}
        source={{ uri: `data:image/jpeg;base64,${decryptedImage}` }}
      />
      <Image
        style={{ width: 120, height: 100 }}
        source={{ uri: `data:image/jpeg;base64,${decryptedImageThreeMb}` }}
      />
    </>
  );
};
