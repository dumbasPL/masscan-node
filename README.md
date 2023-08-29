# masscan-node

Node.js wrapper for [masscan](https://github.com/robertdavidgraham/masscan).

## Installation

only supported on linux. requires masscan to already be installed.  
please make an [issue](https://github.com/dumbasPL/masscan-node/issues/new) if you need support for other platforms.

```bash
yard add masscan-node
# or
npm install masscan-node
```

## Usage

```js
const {Masscan} = require('masscan-node');

// scan the whole internet for open ports 80 and 443 at 10k packets per second
// see original masscan docs for more info on the available options
const masscan = new Masscan({
  ports: '80,443',
  range: '0.0.0.0/0',
  exclude: '255.255.255.255',
  rate: 10000,
}, '/usr/bin/masscan');

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
});
```

## Example output

Check out [masscan.d.ts](./dist/masscan.d.ts) for all the possible outputs.

### Example status

```js
{
  ip: '1.1.1.1',
  timestamp: '1693342291',
  port: 80,
  proto: 'tcp',
  rec_type: 'status',
  data: { status: 'open', reason: 'syn-ack', ttl: 236 }
}
```

### Example stat

```js
{
  state: 'running',
  rate: { kpps: 9.96, pps: 9960.26 },
  progress: {
    percent: 0,
    eta: { hours: 935, mins: 48, seconds: 20 },
    syn: { sent: 7652, total: 4294967295, remaining: 4294959643 },
    found: 82
  }
}
```
