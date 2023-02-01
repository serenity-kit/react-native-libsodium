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
      <View>{children}</View>
    </View>
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
  },
  output: {
    flexDirection: 'row',
  },
});
