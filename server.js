const express = require('express');
const { spawn } = require('child_process');
const path = require('path');

const app = express();
const port = 8080;

// Middleware
app.use(express.json()); // For parsing application/json

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// API endpoint to run network tools
app.post('/api/net-tool', (req, res) => {
  // Destructure new parameters
  const { tool, host, dnsServer, port, protocol, debug } = req.body;

  let command;
  let args = [];

  // --- Input Sanitization and Command Building ---

  // Whitelist allowed tools
  if (!['ping', 'nslookup', 'traceroute', 'mtr', 'openssl_sconnect'].includes(tool)) {
    return res.status(400).send('Error: Invalid tool specified.');
  }

  // Sanitize host: Allow FQDNs, IPv4, and IPv6
  if (!host || !/^[a-zA-Z0-9\.:\-\_]+$/.test(host)) {
    return res.status(400).send('Error: Invalid hostname or IP address.');
  }

  // Sanitize DNS server (if provided)
  if (dnsServer && !/^[a-zA-Z0-9\.:\-\_]+$/.test(dnsServer)) {
    return res.status(400).send('Error: Invalid DNS server address.');
  }
  
  // Sanitize Port (if provided)
  let validPort = null;
  if (port) {
    const parsedPort = parseInt(port, 10);
    if (!isNaN(parsedPort) && parsedPort > 0 && parsedPort <= 65535) {
      validPort = parsedPort;
    } else {
      return res.status(400).send('Error: Invalid port specified.');
    }
  }
  const connectPort = validPort || 443; // Default to 443
  
  // Sanitize Protocol (if provided)
  if (protocol && !['tcp', 'udp'].includes(protocol)) {
    return res.status(400).send('Error: Invalid protocol specified.');
  }
  
  // Sanitize Debug (if provided)
  const isDebug = !!debug;
  
  // --- End Sanitization ---


  switch (tool) {
    case 'ping':
      command = 'ping';
      args = ['-c', '4', host];
      break;
      
    case 'nslookup':
      command = 'nslookup';
      args = [];
      if (isDebug) {
        args.push('-debug');
      }
      args.push(host);
      if (dnsServer) {
        args.push(dnsServer);
      }
      break;
      
    case 'traceroute':
      command = 'traceroute';
      args = ['-w', '3', '-q', '1', '-m', '20', host];
      break;
      
    case 'mtr':
      command = 'mtr';
      // -r (report mode), -c 5 (5 cycles), -n (no DNS)
      args = ['-r', '-w', '-b', '--tcp'];
      
      if (validPort) {
        args.push('-P', connectPort.toString());
      }
      args.push(host);
      break;

    case 'openssl_sconnect':
      command = 'timeout';
      args = [
        '10',
        'openssl',
        's_client',
        '-connect', `${host}:${connectPort}`, // host:port
        '-servername', host                 // SNI support
      ];      
      if (!isDebug) {
        args.push('-brief');
      } else {
        args.push('-showcerts');
      }
      break;
  }

  // --- Process Execution ---
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Transfer-Encoding', 'chunked');

  const child = spawn(command, args);

  // For openssl s_client, we need to send 'Q' to cleanly exit
  if (tool === 'openssl_sconnect') {
    child.stdin.write('Q\n');
    child.stdin.end();
  }

  // Stream stdout
  child.stdout.on('data', (data) => {
    res.write(data);
  });

  // Stream stderr
  child.stderr.on('data', (data) => {
    res.write(data);
  });

  // Handle process exit
  child.on('close', (code) => {
    res.write(`\n--- Process finished ---`);
    res.end();
  });

  // Handle errors
  child.on('error', (err) => {
    console.error(`Failed to start subprocess: ${err}`);
    res.write(`\n--- ERROR: Failed to start subprocess ${err.message} ---`);
    res.end();
  });
});

// Serve static assets (if any)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

