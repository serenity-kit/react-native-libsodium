import { AppRegistry, Platform } from 'react-native';
import App from './src/App';
// import { name as appName } from './app.json';

AppRegistry.registerComponent('LibsodiumExample', () => App);

if (Platform.OS === 'web') {
  AppRegistry.runApplication('LibsodiumExample', {
    rootTag: document.getElementById('react-root'),
  });
}
