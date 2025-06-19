const axios = require('axios');
const fs = require('fs');
const cheerio = require('cheerio');

const oxylabsUsername = 'pankaj_jOilq';
const oxylabsPassword = 'PankajRajput123_';
const base64Auth = Buffer.from(`${oxylabsUsername}:${oxylabsPassword}`).toString('base64');

const targetUrl = 'https://worldwide.espacenet.com/patent/search/family/042199146/publication/US8900904B2?q=US8900904B2';

const oxylabsUrl = 'https://realtime.oxylabs.io/v1/queries';
const payload = {
  source: 'universal',
  url: targetUrl,
  geo_location: 'United States',
  render: 'html',
  context: [
    { key: 'follow_redirections', value: true },
    { key: 'wait_for', value: 15000 },
    { key: 'timeout', value: 30000 }
  ],
};

axios.post(oxylabsUrl, payload, {
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Basic ${base64Auth}`,
  },
  timeout: 40000,
})
.then(response => {
  const result = response.data.results[0];
  if (!result.content) {
    console.error('⚠️ No content found');
    return;
  }

  const $ = cheerio.load(result.content);
  let output = '';

  // Example selectors — tune them based on real HTML
  const title = $('h1, h2, .title').first().text().trim();
  const abstract = $('section:contains("Abstract")').text().trim() || $('div.abstract').text().trim();
  const inventors = $('span:contains("Inventor"), div:contains("Inventor")').next().text().trim();
  const applicants = $('span:contains("Applicant"), div:contains("Applicant")').next().text().trim();
  const pubNumber = $('span:contains("Publication number")').next().text().trim();

  output += `📌 Title: ${title || 'Not Found'}\n`;
  output += `📌 Abstract: ${abstract || 'Not Found'}\n`;
  output += `📌 Inventors: ${inventors || 'Not Found'}\n`;
  output += `📌 Applicants: ${applicants || 'Not Found'}\n`;
  output += `📌 Publication Number: ${pubNumber || 'Not Found'}\n`;

  // ✅ Print to console
  console.log('\n📄 Extracted Patent Data:\n');
  console.log(output);

  // ✅ Save to file
  fs.writeFileSync('espacenet_extracted.txt', output);
  console.log('✅ Extracted data saved to espacenet_extracted.txt');
})
.catch(error => {
  if (error.response) {
    console.error('❌ API Error:', error.response.status, error.response.data);
  } else {
    console.error('❌ Request Error:', error.message);
  }
});
