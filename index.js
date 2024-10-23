const express = require('express');
const dns = require('dns');
const axios = require('axios');

const app = express();
const port = 3000;

// Your VirusTotal API key
const apiKey = '368c4a22cd7abe038b8945047f3df94151c5bef43f58ef0e309d3a599333f8fa';

/**
 * Function to fetch domains related to an IP address using VirusTotal's API.
 * @param {string} ip - The IP address to query.
 * @returns {Promise<Array<string>>} - An array of domain names related to the IP.
 */
async function getDomainsByIp(ip) {
  const url = `https://www.virustotal.com/vtapi/v2/ip-address/report`;
  const params = {
    ip: ip,
    apikey: apiKey,
  };

  try {
    const response = await axios.get(url, { params });
    const data = response.data;

    if (data.response_code === 1 && data.resolutions) {
      return data.resolutions.map((resolution) => resolution.hostname);
    } else {
      return [];
    }
  } catch (error) {
    console.error(`Error fetching domains for IP ${ip}:`, error.message);
    return [];
  }
}

app.get('/clones', (req, res) => {
  var url = req.query.url;
  if(new URL(url)){
    url = url.hostname;
  }
  if (!url) {
    return res.status(400).send({ error: 'URL parameter is required' });
  }

  // Resolve the IP address for the given URL
  dns.lookup(url, async (err, address) => {
    if (err) {
      console.error(`DNS lookup failed for URL ${url}:`, err.message);
      return res.status(500).send({ error: 'Failed to resolve IP address' });
    }

    console.log(`Resolved IP address for ${url}: ${address}`);

    // Get domains associated with the IP
    const domains = await getDomainsByIp(address);

    res.send({ ip: address, domains });
  });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
