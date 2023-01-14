import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

type Props = {
  children?: React.ReactNode;
};

export const Header: React.FC<Props> = ({ children }) => {
  return (
    <View style={styles.container}>
      <Text style={styles.headerText}>{children}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    backgroundColor: '#aaa',
    borderBottomWidth: 1,
    width: '100%',
    paddingVertical: 10,
    paddingHorizontal: 5,
  },
  headerText: {
    fontWeight: 'bold',
  },
});
