const fetch = require('node-fetch');
const cheerio = require('cheerio');

const scrapeEspacenetPatent = async (url) => {
  console.log(`Scraping Espacenet URL: ${url}`);

  const fetchHeaders = {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    Accept:
      'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    Referer: 'https://worldwide.espacenet.com/',
    Connection: 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
  };

  try {
    const response = await fetch(url, {
      headers: fetchHeaders,
      redirect: 'follow',
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch Espacenet URL: ${response.statusText}`);
    }

    const html = await response.text();
    const $ = cheerio.load(html);

    // Scrape basic patent details
    const title = $('h1#title').text().trim() || $('meta[name="DC.title"]').attr('content')?.trim() || 'N/A';
    const abstract = $('div#abstract p').text().trim() || 'N/A';

    // Scrape inventors
    const inventors = $('span[itemprop="inventor"]')
      .map((i, el) => $(el).text().trim())
      .get()
      .filter(name => name) || [];

    const publicationNumber = $('span[itemprop="publicationNumber"]').text().trim() || url.split('/').pop() || 'N/A';
    const publicationDate = $('time[itemprop="publicationDate"]').text().trim() || 'N/A';
    const filingDate = $('time[itemprop="filingDate"]').text().trim() || 'N/A';
    const assignee = $('span[itemprop="assignee"]').text().trim() || 'N/A';
    const status = $('span[itemprop="status"]').text().trim() || 'N/A';
    const priorityDate = $('time[itemprop="priorityDate"]').text().trim() || 'N/A';

    // Scrape classifications (CPC/IPC)
    const classifications = $('div#classifications span[itemprop="cpcs"]')
      .map((i, el) => {
        const code = $(el).find('span[itemprop="Code"]').text().trim() || $(el).text().trim().split(' - ')[0];
        const description = $(el).find('span[itemprop="Description"]').text().trim() || $(el).text().trim().split(' - ')[1] || '';
        return { code, description };
      })
      .get();

    // Scrape citations
    const citations = $('tr[itemprop="backwardReferences"]')
      .map((i, el) => {
        const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || 'N/A';
        const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || 'N/A';
        const title = $(el).find('td[itemprop="title"]').text().trim() || 'N/A';
        const assignee = $(el).find('td[itemprop="assignee"]').text().trim() || 'N/A';
        return { number, date, title, assignee };
      })
      .get();

    // Scrape cited by
    const citedBy = $('tr[itemprop="forwardReferences"]')
      .map((i, el) => {
        const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || 'N/A';
        const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || 'N/A';
        const title = $(el).find('td[itemprop="title"]').text().trim() || 'N/A';
        const assignee = $(el).find('td[itemprop="assignee"]').text().trim() || 'N/A';
        return { number, date, title, assignee };
      })
      .get();

    // Scrape legal events
    const legalEvents = $('tr[itemprop="legalEvents"]')
      .map((i, el) => {
        const date = $(el).find('time[itemprop="date"]').text().trim() || 'N/A';
        const description = $(el).find('td[itemprop="description"]').text().trim() || 'N/A';
        return { date, description };
      })
      .get();

    // Scrape patent family
    const patentFamily = $('tr[itemprop="family"]')
      .map((i, el) => {
        const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || 'N/A';
        const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || 'N/A';
        const country = $(el).find('td[itemprop="country"]').text().trim() || 'N/A';
        return { number, date, country };
      })
      .get();

    // Scrape drawings
    const drawingsFromCarousel = [];
    $('img[itemprop="thumbnail"]').each((i, elem) => {
      const src = $(elem).attr('src');
      if (src) drawingsFromCarousel.push(src);
    });

    // Scrape claims and description
    const claims = $('section[itemprop="claims"]').html() || '';
    const description = $('section[itemprop="description"]').html() || '';

    // Scrape similar documents
    const similarDocs = $('tr[itemprop="similarDocuments"]')
      .map((i, el) => {
        const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || 'N/A';
        const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || 'N/A';
        const title = $(el).find('td[itemprop="title"]').text().trim() || 'N/A';
        return { number, date, title };
      })
      .get();

    // Scrape PDF URL (Espacenet often links to a PDF, we can try to find it)
    let pdfUrl = null;
    const pdfLink = $('a[href*=".pdf"]').attr('href');
    if (pdfLink) {
      pdfUrl = pdfLink.startsWith('http') ? pdfLink : `https://worldwide.espacenet.com${pdfLink}`;
    }

    const patentData = {
      type: 'patent',
      source: 'espacenet',
      data: {
        title,
        abstract,
        inventors,
        publicationNumber,
        publicationDate,
        filingDate,
        assignee,
        status,
        priorityDate,
        classifications,
        citations,
        citedBy,
        legalEvents,
        patentFamily,
        drawings: [],
        drawingsFromCarousel,
        claims,
        description,
        similarDocs,
        pdfUrl,
      },
    };

    console.log('Extracted Espacenet Patent Data:', JSON.stringify(patentData, null, 2));
    return patentData;
  } catch (error) {
    console.error('Espacenet scraping error:', error.message);
    throw error;
  }
};

module.exports = { scrapeEspacenetPatent };