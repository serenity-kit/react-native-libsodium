import React from 'react';
import { Image } from 'react-native';
import { largeContent } from '../largeContent';
import { threeMbImage } from '../threeMbImage';
import { encryptAndDecryptImage } from '../utils/encryptAndDecryptImage';

export const VisualImageTest: React.FC = () => {
  const decryptedImage = encryptAndDecryptImage(threeMbImage);
  const decryptedLargeImage = encryptAndDecryptImage(largeContent);

  return (
    <>
      <Image
        style={{ width: 120, height: 100 }}
        source={{ uri: `data:image/jpeg;base64,${decryptedImage}` }}
      />
      <Image
        style={{ width: 120, height: 100 }}
        source={{ uri: `data:image/jpeg;base64,${decryptedLargeImage}` }}
      />
    </>
  );
};
