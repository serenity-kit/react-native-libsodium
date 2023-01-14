import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

type Props = {
  name: string;
  success: boolean;
  children?: React.ReactNode;
};

export const FunctionStatus: React.FC<Props> = ({
  name,
  success,
  children,
}) => {
  return (
    <View style={styles.container}>
      <View style={styles.result}>
        <View>
          <Text>{success ? '✅ ' : '❌ '}</Text>
        </View>
        <View>
          <Text>{name}</Text>
        </View>
      </View>
      <View style={styles.children}>
        <Text>{children}</Text>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    borderColor: 'black',
    borderBottomWidth: 1,
    width: '100%',
    paddingVertical: 10,
    paddingHorizontal: 5,
  },
  result: {
    display: 'flex',
    flexDirection: 'row',
  },
  children: {
    paddingTop: 5,
  },
});
