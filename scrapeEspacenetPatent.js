// const puppeteer = require('puppeteer-extra');
// const StealthPlugin = require('puppeteer-extra-plugin-stealth');
// const cheerio = require('cheerio');
// const fetch = require('node-fetch');

// // Add stealth plugin to puppeteer
// puppeteer.use(StealthPlugin());

// const fetchWithTimeout = async (url, options, timeout = 10000) => {
//   const controller = new AbortController();
//   const id = setTimeout(() => controller.abort(), timeout);
//   try {
//     const response = await fetch(url, { ...options, signal: controller.signal });
//     clearTimeout(id);
//     return response;
//   } catch (error) {
//     clearTimeout(id);
//     throw error;
//   }
// };

// const retryFetch = async (url, options, retries = 3, delay = 1000) => {
//   for (let i = 0; i < retries; i++) {
//     try {
//       return await fetchWithTimeout(url, options);
//     } catch (error) {
//       if (i === retries - 1) throw error;
//       console.log(`Fetch failed, retrying (${i + 1}/${retries})...`, error.message);
//       await new Promise(resolve => setTimeout(resolve, delay));
//     }
//   }
// };

// async function scrapeEspacenetPatent(targetUrl, fetchHeaders, res) {
//   let browser;
//   try {
//     console.log(`Fetching Espacenet URL with Puppeteer: ${targetUrl}`);

//     // Launch Puppeteer with stealth
//     browser = await puppeteer.launch({
//       headless: true,
//       args: [
//         '--no-sandbox',
//         '--disable-setuid-sandbox',
//         '--disable-dev-shm-usage',
//         '--disable-accelerated-2d-canvas',
//         '--disable-gpu',
//         '--window-size=1920,1080',
//       ],
//     });
//     const page = await browser.newPage();

//     // Set headers and viewport to mimic a real browser
//     await page.setUserAgent(fetchHeaders['User-Agent']);
//     await page.setExtraHTTPHeaders({
//       'Accept': fetchHeaders['Accept'],
//       'Accept-Language': fetchHeaders['Accept-Language'],
//       'Referer': 'https://worldwide.espacenet.com/',
//     });
//     await page.setViewport({ width: 1920, height: 1080 });

//     // Navigate to the page and wait for content to load
//     await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 60000 });

//     // Wait for specific elements to ensure dynamic content is loaded
//     await page.waitForSelector('h1, meta[name="DC.title"], title', { timeout: 10000 }).catch(() => {
//       console.log('Title selector not found, proceeding with available content');
//     });
//     await page.waitForSelector('section[itemprop="abstract"], div.abstract, meta[name="description"]', { timeout: 10000 }).catch(() => {
//       console.log('Abstract selector not found, proceeding with available content');
//     });

//     // Add a delay to ensure all dynamic content loads (including potential Cloudflare checks)
//     await new Promise(resolve => setTimeout(resolve, 5000));

//     // Get the page content
//     const html = await page.content();
//     console.log('Fetched HTML length:', html.length);
//     console.log('Raw HTML snippet:', html.slice(0, 2000));

//     const $ = cheerio.load(html);

//     // Updated selectors for title
//     const title = $('h1[itemprop="inventionTitle"]').text().trim() || 
//                   $('h3[itemprop="inventionTitle"]').text().trim() || 
//                   $('meta[name="DC.title"]').attr('content')?.trim() || 
//                   $('title').text().trim().split(' - ')[0] || 
//                   $('h1').first().text().trim() || '';
//     console.log('Title:', title);

//     // Check for Cloudflare's "Just a moment..." page
//     if (title.toLowerCase().includes('just a moment')) {
//       console.log('Detected Cloudflare bot protection. Falling back to Google Patents...');
//       throw new Error('Cloudflare bot protection detected');
//     }

//     // Updated selectors for abstract
//     const abstract = $('section[itemprop="abstract"]').text().trim() || 
//                      $('div[itemprop="abstract"]').text().trim() || 
//                      $('div.abstract').text().trim() || 
//                      $('meta[name="description"]').attr('content')?.trim() || 
//                      $('p[itemprop="abstract"]').text().trim() || '';
//     console.log('Abstract:', abstract);

//     const publicationNumberRaw = $('span[itemprop="publicationNumber"]').text().trim() || 
//                                 targetUrl.match(/pn%3D([A-Z0-9]+)/)?.[1] || '';
//     const publicationNumber = publicationNumberRaw.match(/[A-Z]{2}[0-9A-Z]+/g)?.join(', ') || publicationNumberRaw;
//     console.log('Publication Number:', publicationNumber);

//     const inventors = $('span[itemprop="inventor"]').map((i, el) => $(el).text().trim()).get().filter(name => name) || [];
//     console.log('Inventors:', inventors);

//     const publicationDateRaw = $('time[itemprop="publicationDate"]').text().trim() || 
//                               $('span[itemprop="publicationDate"]').text().trim() || '';
//     const publicationDateMatch = publicationDateRaw.match(/\d{4}-\d{2}-\d{2}/) || [];
//     const publicationDate = publicationDateMatch[0] || publicationDateRaw;
//     console.log('Publication Date:', publicationDate);

//     const filingDate = $('time[itemprop="filingDate"]').text().trim() || 
//                        $('span[itemprop="filingDate"]').text().trim() || '';
//     console.log('Filing Date:', filingDate);

//     const assignee = $('span[itemprop="assignee"]').text().trim() || 
//                      $('span[itemprop="applicant"]').text().trim() || '';
//     console.log('Assignee:', assignee);

//     const priorityDateRaw = $('span[itemprop="priorityDate"]').text().trim() || '';
//     const priorityDateMatch = priorityDateRaw.split(';').map(date => date.trim()).filter(date => date.match(/\d{4}-\d{2}-\d{2}/)) || [];
//     const priorityDate = priorityDateMatch.join('; ') || priorityDateRaw;
//     console.log('Priority Date:', priorityDate);

//     const classifications = [];
//     $('span[itemprop="ipc"], span[itemprop="cpc"]').each((i, el) => {
//       const code = $(el).find('span[itemprop="Code"]').text().trim() || $(el).text().trim().split(' - ')[0] || $(el).text().trim();
//       const description = $(el).find('span[itemprop="Description"]').text().trim() || $(el).text().trim().split(' - ').slice(1).join(' - ') || '';
//       if (code) classifications.push({ code, description });
//     });
//     console.log('Classifications:', classifications);

//     const citations = $('tr[itemprop="backwardReferences"]').map((i, el) => {
//       const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
//       const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
//       const title = $(el).find('td[itemprop="title"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
//       const assignee = $(el).find('td[itemprop="assignee"]').text().trim() || $(el).find('td:nth-child(4)').text().trim();
//       return { number, date, title, assignee };
//     }).get();
//     console.log('Citations:', citations);

//     const citedBy = $('tr[itemprop="forwardReferences"]').map((i, el) => {
//       const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
//       const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
//       const title = $(el).find('td[itemprop="title"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
//       const assignee = $(el).find('td[itemprop="assignee"]').text().trim() || $(el).find('td:nth-child(4)').text().trim();
//       return { number, date, title, assignee };
//     }).get();
//     console.log('Cited By:', citedBy);

//     const legalEvents = $('tr[itemprop="legalEvents"]').map((i, el) => {
//       const date = $(el).find('time[itemprop="date"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
//       const description = $(el).find('td[itemprop="description"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
//       return { date, description };
//     }).get();
//     console.log('Legal Events:', legalEvents);

//     const patentFamily = $('tr[itemprop="patentFamily"]').map((i, el) => {
//       const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
//       const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
//       const country = $(el).find('td[itemprop="country"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
//       return { number, date, country };
//     }).get();
//     console.log('Patent Family:', patentFamily);

//     const applicationEvents = [];
//     if (filingDate) {
//       applicationEvents.push({ date: filingDate, title: `Application filed by ${assignee || 'Unknown Assignee'}` });
//     }
//     if (publicationDate) {
//       applicationEvents.push({ date: publicationDate, title: `Publication of ${publicationNumber || 'Unknown Publication'}` });
//     }
//     legalEvents.forEach(event => {
//       if (event.date && event.description) {
//         applicationEvents.push({ date: event.date, title: event.description });
//       }
//     });
//     applicationEvents.sort((a, b) => {
//       const dateA = a.date.match(/\d{4}-\d{2}-\d{2}/) ? new Date(a.date) : Infinity;
//       const dateB = b.date.match(/\d{4}-\d{2}-\d{2}/) ? new Date(b.date) : Infinity;
//       return dateA - dateB;
//     });
//     console.log('Application Events:', applicationEvents);

//     const claims = $('section[itemprop="claims"]').html() || $('div.claims').html() || '';
//     console.log('Claims length:', claims.length);

//     const description = $('section[itemprop="description"]').html() || $('div.description').html() || '';
//     console.log('Description length:', description.length);

//     const drawingsFromCarousel = [];
//     $('img[itemprop="thumbnail"], meta[itemprop="image"]').each((i, elem) => {
//       const src = $(elem).attr('src') || $(elem).attr('content');
//       if (src && (src.startsWith('http') || src.startsWith('/'))) {
//         drawingsFromCarousel.push(src.startsWith('http') ? src : `https://worldwide.espacenet.com${src}`);
//       }
//     });
//     console.log('Drawings:', drawingsFromCarousel);

//     const similarDocs = $('tr[itemprop="similarDocuments"]').map((i, el) => {
//       const number = $(el).find('td[itemprop="publicationNumber"]').text().trim() || $(el).find('td:nth-child(1)').text().trim();
//       const date = $(el).find('time[itemprop="publicationDate"]').text().trim() || $(el).find('td:nth-child(2)').text().trim();
//       const title = $(el).find('td[itemprop="title"]').text().trim() || $(el).find('td:nth-child(3)').text().trim();
//       return { number, date, title };
//     }).get();
//     console.log('Similar Docs:', similarDocs);

//     let pdfUrl = $('a[href*=".pdf"][itemprop="originalDocument"]').attr('href') || null;
//     if (pdfUrl && !pdfUrl.startsWith('http')) {
//       pdfUrl = `https://worldwide.espacenet.com${pdfUrl}`;
//     }
//     if (pdfUrl) {
//       try {
//         const pdfResponse = await retryFetch(pdfUrl, { headers: fetchHeaders, redirect: 'follow', method: 'HEAD' });
//         if (!pdfResponse.ok) {
//           console.log(`Espacenet PDF fetch failed with status: ${pdfResponse.status}`);
//           pdfUrl = null;
//         }
//       } catch (err) {
//         console.error('Failed to verify Espacenet PDF URL:', err.message);
//         pdfUrl = null;
//       }
//     }

//     if (!pdfUrl && publicationNumber) {
//       const googlePdfUrl = `https://patentimages.storage.googleapis.com/patents/${publicationNumber.toLowerCase()}.pdf`;
//       try {
//         const verifyResponse = await retryFetch(googlePdfUrl, { headers: fetchHeaders, redirect: 'follow', method: 'HEAD' });
//         if (verifyResponse.ok) {
//           pdfUrl = googlePdfUrl;
//           console.log('Fallback: Using Google Patents PDF URL:', googlePdfUrl);
//         }
//       } catch (err) {
//         console.error('Fallback: Failed to verify Google Patents PDF URL:', err.message);
//       }
//     }
//     console.log('PDF URL:', pdfUrl);

//     const patentData = {
//       type: 'patent',
//       source: 'espacenet',
//       data: {
//         title,
//         abstract,
//         inventors,
//         publicationNumber,
//         publicationDate,
//         filingDate,
//         assignee,
//         priorityDate,
//         classifications,
//         citations,
//         citedBy,
//         legalEvents,
//         patentFamily,
//         applicationEvents,
//         drawings: [],
//         drawingsFromCarousel,
//         claims,
//         description,
//         similarDocs,
//         pdfUrl,
//       },
//     };

//     console.log('Extracted Espacenet Patent Data:', JSON.stringify(patentData, null, 2));

//     await browser.close();
//     res.json(patentData);
//   } catch (error) {
//     console.error('Espacenet Scraping Error:', error.message);
//     if (browser) await browser.close();

//     // Fallback to Google Patents if Espacenet scraping fails
//     console.log('Falling back to Google Patents due to Espacenet scraping failure...');
//     try {
//       const publicationNumberMatch = targetUrl.match(/([A-Z]{2}\d+[A-Z]\d?)/)?.[0] || '';
//       if (!publicationNumberMatch) {
//         throw new Error('Could not extract publication number for Google Patents fallback');
//       }

//       const googlePatentsUrl = `https://patents.google.com/patent/${publicationNumberMatch}`;
//       console.log(`Fetching from Google Patents: ${googlePatentsUrl}`);

//       // Use Puppeteer for Google Patents
//       browser = await puppeteer.launch({
//         headless: true,
//         args: [
//           '--no-sandbox',
//           '--disable-setuid-sandbox',
//           '--disable-dev-shm-usage',
//           '--disable-accelerated-2d-canvas',
//           '--disable-gpu',
//           '--window-size=1920,1080',
//         ],
//       });
//       const googlePage = await browser.newPage();
//       await googlePage.setUserAgent(fetchHeaders['User-Agent']);
//       await googlePage.setExtraHTTPHeaders({
//         'Accept': fetchHeaders['Accept'],
//         'Accept-Language': fetchHeaders['Accept-Language'],
//         'Referer': 'https://patents.google.com/',
//       });
//       await googlePage.setViewport({ width: 1920, height: 1080 });
//       await googlePage.goto(googlePatentsUrl, { waitUntil: 'networkidle2', timeout: 60000 });

//       const googleHtml = await googlePage.content();
//       const $google = cheerio.load(googleHtml);

//       const googleTitle = $google('h2#title').text().trim() || $google('meta[name="DC.title"]').attr('content')?.trim() || $google('title').text().trim();
//       const googleAbstract = $google('div.abstract').text().trim() || $google('section[itemprop="abstract"] p').text().trim() || '';
//       const googleInventors = $google('[itemprop="inventor"]').map((i, el) => $google(el).text().trim()).get().filter(name => name);
//       const googlePublicationNumber = publicationNumberMatch.match(/[A-Z]{2}[0-9A-Z]+/g)?.join(', ') || publicationNumberMatch;
//       const googlePublicationDate = $google('time[itemprop="publicationDate"]').text().trim();
//       const googleFilingDate = $google('time[itemprop="filingDate"]').text().trim();
//       const googleAssignee = $google('dd[itemprop="assigneeOriginal"]').text().trim();
//       const googlePriorityDate = $google('time[itemprop="priorityDate"]').text().trim();
//       const googleClassifications = $google('span[itemprop="cpcs"]').map((i, el) => {
//         const code = $google(el).find('span[itemprop="Code"]').text().trim() || $google(el).text().trim().split(' - ')[0];
//         const description = $google(el).find('span[itemprop="Description"]').text().trim() || $google(el).text().trim().split(' - ').slice(1).join(' - ') || '';
//         return { code, description };
//       }).get();
//       const googleCitations = $google('tr[itemprop="backwardReferences"]').map((i, el) => {
//         const number = $google(el).find('td[itemprop="publicationNumber"]').text().trim();
//         const date = $google(el).find('time[itemprop="publicationDate"]').text().trim();
//         const title = $google(el).find('td[itemprop="title"]').text().trim();
//         const assignee = $google(el).find('td[itemprop="assignee"]').text().trim();
//         return { number, date, title, assignee };
//       }).get();
//       const googleCitedBy = $google('tr[itemprop="forwardReferences"]').map((i, el) => {
//         const number = $google(el).find('td[itemprop="publicationNumber"]').text().trim();
//         const date = $google(el).find('time[itemprop="publicationDate"]').text().trim();
//         const title = $google(el).find('td[itemprop="title"]').text().trim();
//         const assignee = $google(el).find('td[itemprop="assignee"]').text().trim();
//         return { number, date, title, assignee };
//       }).get();
//       const googleLegalEvents = $google('tr[itemprop="legalEvents"]').map((i, el) => {
//         const date = $google(el).find('time[itemprop="date"]').text().trim();
//         const description = $google(el).find('td[itemprop="description"]').text().trim();
//         return { date, description };
//       }).get();
//       const googlePatentFamily = $google('tr[itemprop="family"]').map((i, el) => {
//         const number = $google(el).find('td[itemprop="publicationNumber"]').text().trim();
//         const date = $google(el).find('time[itemprop="publicationDate"]').text().trim();
//         const country = $google(el).find('td[itemprop="country"]').text().trim();
//         return { number, date, country };
//       }).get();
//       const googleApplicationEvents = [];
//       if (googleFilingDate) {
//         googleApplicationEvents.push({ date: googleFilingDate, title: `Application filed by ${googleAssignee || 'Unknown Assignee'}` });
//       }
//       if (googlePublicationDate) {
//         googleApplicationEvents.push({ date: googlePublicationDate, title: `Publication of ${googlePublicationNumber || 'Unknown Publication'}` });
//       }
//       googleLegalEvents.forEach(event => {
//         if (event.date && event.description) {
//           googleApplicationEvents.push({ date: event.date, title: event.description });
//         }
//       });
//       googleApplicationEvents.sort((a, b) => new Date(a.date) - new Date(b.date));

//       const googleClaims = $google('section[itemprop="claims"]').html() || '';
//       const googleDescription = $google('section[itemprop="description"]').html() || '';
//       const googleDrawings = [];
//       $google('meta[itemprop="full"]').each((i, elem) => {
//         const content = $google(elem).attr('content');
//         if (content) googleDrawings.push(content);
//       });
//       const googleSimilarDocs = $google('tr[itemprop="similarDocuments"]').map((i, el) => {
//         const number = $google(el).find('td[itemprop="publicationNumber"]').text().trim();
//         const date = $google(el).find('time[itemprop="publicationDate"]').text().trim();
//         const title = $google(el).find('td[itemprop="title"]').text().trim();
//         return { number, date, title };
//       }).get();

//       let googlePdfUrl = null;
//       const pdfEndpoint = googlePatentsUrl.endsWith('/') ? `${googlePatentsUrl}pdf` : `${googlePatentsUrl}/pdf`;
//       try {
//         const pdfResponse = await retryFetch(pdfEndpoint, { headers: fetchHeaders, redirect: 'follow', method: 'HEAD' });
//         if (pdfResponse.ok && pdfResponse.url.includes('patentimages.storage.googleapis.com') && pdfResponse.url.endsWith('.pdf')) {
//           googlePdfUrl = pdfResponse.url;
//         }
//       } catch (err) {
//         console.error('Failed to fetch Google Patents PDF endpoint:', err.message);
//       }

//       const fallbackPatentData = {
//         type: 'patent',
//         source: 'google',
//         data: {
//           title: googleTitle,
//           abstract: googleAbstract,
//           inventors: googleInventors,
//           publicationNumber: googlePublicationNumber,
//           publicationDate: googlePublicationDate,
//           filingDate: googleFilingDate,
//           assignee: googleAssignee,
//           priorityDate: googlePriorityDate,
//           classifications: googleClassifications,
//           citations: googleCitations,
//           citedBy: googleCitedBy,
//           legalEvents: googleLegalEvents,
//           patentFamily: googlePatentFamily,
//           applicationEvents: googleApplicationEvents,
//           drawings: [],
//           drawingsFromCarousel: googleDrawings,
//           claims: googleClaims,
//           description: googleDescription,
//           pdfUrl: googlePdfUrl,
//         },
//       };

//       console.log('Extracted Google Patents Data:', JSON.stringify(fallbackPatentData, null, 2));
//       await googlePage.close();
//       await browser.close();
//       res.json(fallbackPatentData);
//     } catch (fallbackError) {
//       console.error('Google Patents Fallback Error:', fallbackError.message);
//       if (browser) await browser.close();
//       res.status(503).json({ error: `Failed to scrape patent data from both Espacenet and Google Patents: ${fallbackError.message}` });
//     }
//   }
// }

// module.exports = scrapeEspacenetPatent;