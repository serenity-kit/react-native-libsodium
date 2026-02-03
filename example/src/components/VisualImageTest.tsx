import React from 'react';
import { Image, StyleSheet } from 'react-native';
import { largeContent } from '../largeContent';
import { threeMbImage } from '../threeMbImage';
import { encryptAndDecryptImage } from '../utils/encryptAndDecryptImage';

export const VisualImageTest: React.FC = () => {
  const decryptedImage = encryptAndDecryptImage(threeMbImage);
  const decryptedLargeImage = encryptAndDecryptImage(largeContent);

  return (
    <>
      <Image
        style={styles.image}
        source={{ uri: `data:image/jpeg;base64,${decryptedImage}` }}
      />
      <Image
        style={styles.image}
        source={{ uri: `data:image/jpeg;base64,${decryptedLargeImage}` }}
      />
    </>
  );
};

const styles = StyleSheet.create({
  image: {
    height: 100,
    width: 120,
  },
});
