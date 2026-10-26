// Sanity: pipeline hljs (VS Code coloring) + ceWrapMatches — simulasi browser
const fs = require('fs');
const https = require('https');

function download(url, dest) {
    return new Promise((resolve, reject) => {
        const f = fs.createWriteStream(dest);
        https.get(url, (res) => {
            if (res.statusCode !== 200) return reject(new Error('HTTP ' + res.statusCode));
            res.pipe(f);
            f.on('finish', () => f.close(resolve));
        }).on('error', reject);
    });
}

(async () => {
    const dest = 'temp_hljs.js';
    if (!fs.existsSync(dest)) {
        await download('https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js', dest);
    }
    const hljs = require('./temp_hljs.js');
    console.log('hljs version:', hljs.version);

    // 1. hljs highlight baris java (persis yang dilakukan ceColorLine)
    const line = '    private static final String BASE_URL = "https://api.stockbit.com/"; // prod';
    const colored = hljs.highlight(line, {language: 'java', ignoreIllegals: true}).value;
    console.log('hljs output:', colored);
    const checks = [
        ['hljs-keyword', 'keyword (biru #569cd6)'],
        ['hljs-string', 'string (oranye #ce9178)'],
        ['hljs-comment', 'comment (hijau #608b4e)'],
        ['hljs-type', 'typename String (#4ec9b0)'],
    ];
    let fail = 0;
    for (const [needle, label] of checks) {
        const ok = colored.includes(needle);
        console.log((ok ? 'PASS' : 'FAIL') + ' - ' + label);
        if (!ok) fail++;
    }
    if (fail) process.exit(1);

    // 2. ceWrapMatches: query emas di dalam output hljs, tanpa merusak span
    const html = fs.readFileSync('templates/results.html', 'utf-8');
    const m = html.match(/function ceWrapMatches\(html\) \{[\s\S]*?\n\}/);
    if (!m) { console.error('ceWrapMatches tidak ketemu'); process.exit(1); }
    global.CE = {highlightQuery: 'api.stockbit.com', regexOn: false, caseOn: false};
    eval(m[0]);
    const wrapped = ceWrapMatches(colored);
    console.log('wrapped   :', wrapped.substring(0, 220));
    const okWrap = wrapped.includes('<span class="ce-hit">api.stockbit.com</span>');
    const intact = wrapped.includes('hljs-string');
    console.log((okWrap ? 'PASS' : 'FAIL') + ' - match emas ter-wrap di dalam string span');
    console.log((intact ? 'PASS' : 'FAIL') + ' - span syntax tetap utuh');
    if (!okWrap || !intact) process.exit(1);

    // 3. bahasa dikenali di bundle common
    for (const lang of ['java', 'kotlin', 'javascript', 'json', 'xml', 'python', 'cpp', 'csharp', 'yaml', 'ini']) {
        if (!hljs.getLanguage(lang)) { console.error('FAIL - bahasa tidak tersedia: ' + lang); process.exit(1); }
    }
    console.log('PASS - semua bahasa peta ekstensi tersedia di bundle');
    console.log('HLJS PIPELINE SANITY: OK');
})().catch(e => { console.error('ERROR:', e.message); process.exit(1); });
