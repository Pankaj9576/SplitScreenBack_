// const fetch = require("node-fetch");
// const cheerio = require("cheerio");
// const fs = require("fs").promises;
// const path = require("path");
// const { fromPath } = require("pdf2pic");

// const imageFilterPatterns = ["patentimages", "full", "highres", "large", "original"];
// const excludePatterns = ["thumbnail", "preview", "small", "medium", "lowres"];

// async function downloadImage(url, outputPath) {
//   try {
//     const response = await fetch(url);
//     if (!response.ok) throw new Error(`Failed to download image: ${response.statusText}`);
//     const buffer = await response.buffer();
//     await fs.writeFile(outputPath, buffer);
//     console.log(`Downloaded image to: ${outputPath}`);
//   } catch (err) {
//     console.error(`Error downloading image ${url}:`, err.message);
//     throw err;
//   }
// }

// async function extractImagesFromPdf(pdfUrl, outputDir) {
//   try {
//     // Download PDF
//     const response = await fetch(pdfUrl);
//     if (!response.ok) throw new Error("Failed to download PDF");
//     const pdfBuffer = await response.buffer();
//     const pdfPath = path.join(outputDir, "temp.pdf");
//     await fs.writeFile(pdfPath, pdfBuffer);

//     // Convert PDF to images
//     const options = {
//       density: 300, // High resolution
//       format: "png",
//       outputDir,
//     };
//     const convert = fromPath(pdfPath, options);
//     const result = await convert.bulk(-1); // Convert all pages
//     const imagePaths = result.map((page) => page.path);

//     // Clean up
//     await fs.unlink(pdfPath);

//     return imagePaths;
//   } catch (err) {
//     console.error("Error extracting images from PDF:", err.message);
//     throw err;
//   }
// }

// async function scrapeFullImageUrls(url, outputDir) {
//   const fullImageUrls = [];
//   let pdfUrl = null;
//   let pdfImages = [];
//   try {
//     await fs.mkdir(outputDir, { recursive: true });

//     const fetchHeaders = {
//       "User-Agent":
//         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
//       Accept:
//         "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
//       "Accept-Language": "en-US,en;q=0.5",
//       Referer: "https://patents.google.com/",
//       Connection: "keep-alive",
//       "Upgrade-Insecure-Requests": "1",
//       "Accept-Encoding": "gzip, deflate, br",
//     };

//     console.log(`Scraping images from: ${url}`);
//     const response = await fetch(url, { headers: fetchHeaders, redirect: "follow" });
//     if (!response.ok) throw new Error(`Failed to fetch URL: ${response.statusText}`);

//     const html = await response.text();
//     const $ = cheerio.load(html);

//     console.log("Found <img> tags:");
//     $("img").each((i, elem) => {
//       const src = $(elem).attr("src");
//       const dataSrc = $(elem).attr("data-src");
//       const dataFullsize = $(elem).attr("data-fullsize") || $(elem).attr("data-highres");
//       console.log(`IMG ${i}: src=${src}, data-src=${dataSrc}, data-fullsize=${dataFullsize}`);
//     });

//     $("img").each((i, elem) => {
//       const src = $(elem).attr("src") || $(elem).attr("data-src") || $(elem).attr("data-fullsize") || $(elem).attr("data-highres");
//       if (src) {
//         if (src.includes("patentimages.storage.googleapis.com")) {
//           const finalUrl = src.startsWith("http") ? src : new URL(src, url).href;
//           fullImageUrls.push(finalUrl);
//         } else if (
//           imageFilterPatterns.some(pattern => src.toLowerCase().includes(pattern)) &&
//           !excludePatterns.some(pattern => src.toLowerCase().includes(pattern))
//         ) {
//           const finalUrl = src.startsWith("http") ? src : new URL(src, url).href;
//           fullImageUrls.push(finalUrl);
//         }
//       }
//     });

//     console.log("Found <a> tags with image-related hrefs:");
//     $("a").each((i, elem) => {
//       const href = $(elem).attr("href");
//       if (href && (href.includes(".png") || href.includes(".jpg") || href.includes(".jpeg"))) {
//         console.log(`A ${i}: href=${href}`);
//       }
//     });

//     $("a").each((i, elem) => {
//       const href = $(elem).attr("href");
//       if (href) {
//         if (href.includes("patentimages.storage.googleapis.com")) {
//           const finalUrl = href.startsWith("http") ? href : new URL(href, url).href;
//           fullImageUrls.push(finalUrl);
//         } else if (
//           (href.includes(".png") || href.includes(".jpg") || href.includes(".jpeg")) &&
//           imageFilterPatterns.some(pattern => href.toLowerCase().includes(pattern)) &&
//           !excludePatterns.some(pattern => href.toLowerCase().includes(pattern))
//         ) {
//           const finalUrl = href.startsWith("http") ? href : new URL(href, url).href;
//           fullImageUrls.push(finalUrl);
//         }
//       }
//     });

//     $("a").each((i, elem) => {
//       const href = $(elem).attr("href");
//       if (href && href.includes(".pdf")) {
//         pdfUrl = href.startsWith("http") ? href : new URL(href, url).href;
//         console.log(`Found PDF: ${pdfUrl}`);
//       }
//     });

//     const uniqueUrls = [...new Set(fullImageUrls)].filter(url => {
//       try {
//         new URL(url);
//         return true;
//       } catch {
//         console.log("Invalid URL skipped:", url);
//         return false;
//       }
//     });

//     console.log("Image URLs Found:");
//     uniqueUrls.forEach((url) => console.log(url));

//     // Download images
//     const downloadedImages = [];
//     for (let i = 0; i < uniqueUrls.length; i++) {
//       const url = uniqueUrls[i];
//       const ext = path.extname(new URL(url).pathname) || ".png";
//       const outputPath = path.join(outputDir, `image_${i}${ext}`);
//       try {
//         await downloadImage(url, outputPath);
//         downloadedImages.push(outputPath);
//       } catch (err) {
//         console.error(`Failed to download ${url}: ${err.message}`);
//       }
//     }

//     // Extract images from PDF if no images were found
//     if (uniqueUrls.length === 0 && pdfUrl) {
//       console.log("No direct images found, extracting from PDF...");
//       try {
//         pdfImages = await extractImagesFromPdf(pdfUrl, outputDir);
//         console.log("PDF Images Extracted:", pdfImages);
//       } catch (err) {
//         console.error("Failed to extract images from PDF:", err.message);
//       }
//     }

//     return {
//       images: uniqueUrls,
//       pdfUrl: pdfUrl || null,
//       downloadedImages: downloadedImages.concat(pdfImages),
//     };
//   } catch (err) {
//     console.error("Error fetching/parsing the page:", err.message);
//     throw err;
//   }
// }

// module.exports = { scrapeFullImageUrls };