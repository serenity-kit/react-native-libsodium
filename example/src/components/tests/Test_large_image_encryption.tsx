import React from 'react';
import { Image, StyleSheet, Text, View } from 'react-native';
import { largeContent } from '../../largeContent';
import { encryptAndDecryptImage } from '../../utils/encryptAndDecryptImage';
import { FunctionStatus } from '../FunctionStatus';

export const Test_large_image_encryption: React.FC = () => {
  const decryptedImage = encryptAndDecryptImage(largeContent);

  return (
    <>
      <FunctionStatus
        name="crypto_aead_xchacha20poly1305_ietf_decrypt"
        success={true}
      >
        <View style={styles.children}>
          <View style={styles.output}>
            <Text style={styles.outputType}>(image)</Text>
            <Image
              style={{ width: 120, height: 100 }}
              source={{ uri: `data:image/jpeg;base64,${decryptedImage}` }}
            />
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
