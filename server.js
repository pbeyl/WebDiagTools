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

// Helper function to execute a command and return output as a promise
function executeCommand(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    let output = '';
    let errorOutput = '';

    child.stdout.on('data', (data) => {
      output += data.toString();
    });

    child.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    child.on('close', (code) => {
      resolve(output + errorOutput);
    });

    child.on('error', (err) => {
      reject(err);
    });
  });
}

// API endpoint to run network tools
app.post('/api/net-tool', (req, res) => {
  // Destructure new parameters
  const { tool, host, hosts, dnsServer, recordType, packetSize, dontFrag, port, protocol, debug } = req.body;

  // --- Input Sanitization and Command Building ---

  // Whitelist allowed tools
  if (!['ping', 'nslookup', 'nslookup_bulk', 'traceroute', 'mtr', 'openssl_sconnect', 'curl'].includes(tool)) {
    return res.status(400).send('Error: Invalid tool specified.');
  }

  // Sanitize host: Allow FQDNs, IPv4, and IPv6
  // For bulk nslookup, host is not required
  if (tool !== 'nslookup_bulk' && (!host || !/^[a-zA-Z0-9\.:\-\_]+$/.test(host))) {
    return res.status(400).send('Error: Invalid hostname or IP address.');
  }

  // Validate hosts for bulk nslookup
  if (tool === 'nslookup_bulk' && !hosts) {
    return res.status(400).send('Error: Please provide hosts for bulk lookup.');
  }

  // Sanitize DNS server (if provided)
  if (dnsServer && !/^[a-zA-Z0-9\.:\-\_]+$/.test(dnsServer)) {
    return res.status(400).send('Error: Invalid DNS server address.');
  }

  // Validate and normalize record type (if provided)
  let validRecordType = null;
  if (recordType) {
    const allowedTypes = ['A','AAAA','CNAME','MX','TXT','NS','SOA','PTR','SRV','ANY'];
    const up = recordType.toString().toUpperCase();
    if (allowedTypes.includes(up)) {
      validRecordType = up;
    } else {
      return res.status(400).send('Error: Invalid DNS record type specified.');
    }
  }

  // Validate ping packet size and don't fragment (if provided)
  let validPacketSize = null;
  const dontFragment = !!dontFrag;
  if (packetSize) {
    const ps = parseInt(packetSize, 10);
    if (!isNaN(ps) && ps >= 0 && ps <= 65535) {
      validPacketSize = ps;
    } else {
      return res.status(400).send('Error: Invalid packet size specified.');
    }
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
  if (protocol) {
    const allowedProtocols = ['tcp', 'udp', 'http', 'https'];
    if (!allowedProtocols.includes(protocol)) {
      return res.status(400).send('Error: Invalid protocol specified.');
    }
  }
  
  // Sanitize Debug (if provided)
  const isDebug = !!debug;
  
  // --- End Sanitization ---

  // Special handling for bulk nslookup
  if (tool === 'nslookup_bulk') {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Transfer-Encoding', 'chunked');

    (async () => {
      try {
        // Parse hosts from the input (one per line)
        const hostList = hosts
          .split('\n')
          .map(h => h.trim())
          .filter(h => h.length > 0);

        if (hostList.length === 0) {
          res.write('Error: No valid hosts provided.');
          res.end();
          return;
        }

        res.write(`Performing NSLookup on ${hostList.length} host(s)...\n\n`);

        // Process each host sequentially
        for (let i = 0; i < hostList.length; i++) {
          const queryHost = hostList[i];

          // Validate each host
          if (!/^[a-zA-Z0-9\.:\-\_]+$/.test(queryHost)) {
            res.write(`\n[${i + 1}/${hostList.length}] Skipping invalid host: ${queryHost}\n`);
            continue;
          }

          res.write(`\n[${i + 1}/${hostList.length}] NSLookup: ${queryHost}\n`);
          res.write(`${'='.repeat(60)}\n`);

          try {
            const args = [];
            if (isDebug) {
              args.push('-debug');
            }
            if (validRecordType) {
              args.push(`-type=${validRecordType}`);
            }
            args.push(queryHost);
            if (dnsServer) {
              args.push(dnsServer);
            }

            const output = await executeCommand('nslookup', args);
            res.write(output);
          } catch (err) {
            res.write(`Error executing nslookup: ${err.message}\n`);
          }
        }

        res.write(`\n\n--- Bulk NSLookup completed ---`);
        res.end();
      } catch (err) {
        console.error('Bulk nslookup error:', err);
        res.write(`\n--- ERROR: ${err.message} ---`);
        res.end();
      }
    })();
    return; // Exit early, don't process further
  }

  let command;
  let args = [];

  switch (tool) {
    case 'ping':
      command = 'ping';
      args = ['-c', '4'];
      if (validPacketSize !== null) {
        args.push('-s', validPacketSize.toString());
      }
      if (dontFragment) {
        // ping options vary; try common flags
        args.push('-M', 'do');
        args.push('-D');
      }
      args.push(host);
      break;
      
    case 'nslookup':
      command = 'nslookup';
      args = [];
      if (isDebug) {
        args.push('-debug');
      }
      if (validRecordType) {
        args.push(`-type=${validRecordType}`);
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

    case 'curl':
      command = 'curl';
      const curlProtocol = (protocol === 'http') ? 'http' : 'https';
      const curlPort = validPort ? `:${validPort}` : '';
      const curlUrl = `${curlProtocol}://${host}${curlPort}`;
      args = [
        '-s',
        '-S',
        '-o', '/dev/null',
        '-w', '\nHTTP Code: %{http_code}\nDNS Lookup: %{time_namelookup}s\nTLS Handshake: %{time_appconnect}s\nTime to First Byte: %{time_starttransfer}s\nTotal Time: %{time_total}s\n',
        curlUrl
      ];
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

