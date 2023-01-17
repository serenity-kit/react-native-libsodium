import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { to_base64 } from 'react-native-libsodium';

type Props = {
  name: string;
  success: boolean;
  output?: any;
  children?: React.ReactNode;
};

export const FunctionStatus: React.FC<Props> = ({
  name,
  success,
  children,
  output,
}) => {
  const getType = (data: any) => {
    const dataType = typeof data;
    if (dataType === 'object') {
      return 'Utf8Array';
    }
    return dataType;
  };

  const formatOutput = (data: any) => {
    const dataType = typeof data;
    if (data === undefined) {
      return 'undefined';
    }
    if (data === null) {
      return 'null';
    }
    if (dataType === 'number' || dataType === 'boolean') {
      return data.toString();
    }
    if (dataType === 'object') {
      return to_base64(data);
    }
    return data;
  };

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
      {output ? (
        <View style={styles.children}>
          <View style={styles.output}>
            <Text style={styles.outputType}>({getType(output)})</Text>
            <Text>{formatOutput(output)}</Text>
          </View>
        </View>
      ) : (
        <View>{children}</View>
      )}
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
