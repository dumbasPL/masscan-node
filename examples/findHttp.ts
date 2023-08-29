
import { Masscan } from '../src/masscan';

const masscan = new Masscan({
  ports: '80',
  range: '0.0.0.0/0',
  exclude: '255.255.255.255',
  rate: 10000,
});

masscan.on('stats', (status) => {
  console.log('stats', status);
});

masscan.on('status', (status) => {
  console.log('status', status);
});

masscan.on('error', (error) => {
  console.log('error', error);
});

masscan.scan().then(() => {
  console.log('done');
}).catch((error) => {
  console.log('scan error', error);
})
