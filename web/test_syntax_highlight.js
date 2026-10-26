// Sanity: syntax highlighter template — ekstrak blok dari results.html lalu uji
const fs = require('fs');
const html = fs.readFileSync('templates/results.html', 'utf-8');
const start = html.indexOf('const CE_KW');
const end = html.indexOf("'g');", start);
if (start < 0 || end < 0) { console.error('blok CE_SYNTAX_RE tidak ketemu'); process.exit(1); }
const block = html.substring(start, end + 5);

global.window = {};
eval(block + "\n;globalThis.CE_SYNTAX_RE = CE_SYNTAX_RE;");  // const di eval scope -> export manual
const CE_SYNTAX_RE = globalThis.CE_SYNTAX_RE;

function escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function ceSyntax(escaped) {
    return escaped.replace(CE_SYNTAX_RE, function (m, cmt, str, kw, num, typ, fn) {
        if (cmt !== undefined) return '<span class="ce-cmt">' + cmt + '</span>';
        if (str !== undefined) return '<span class="ce-str">' + str + '</span>';
        if (kw !== undefined) return '<span class="ce-kw">' + kw + '</span>';
        if (num !== undefined) return '<span class="ce-num">' + num + '</span>';
        if (typ !== undefined) return '<span class="ce-typ">' + typ + '</span>';
        if (fn !== undefined) return '<span class="ce-fn">' + fn + '</span>';
        return m;
    });
}

const sample = escHtml('    private static final String BASE_URL = "https://api.stockbit.com/"; // prod endpoint');
const out = ceSyntax(sample);
console.log('INPUT :', sample);
console.log('OUTPUT:', out);

const checks = [
    ['<span class="ce-kw">private</span>', 'keyword'],
    ['<span class="ce-str">&quot;https://api.stockbit.com/&quot;</span>', 'string'],
    ['<span class="ce-cmt">// prod endpoint</span>', 'comment'],
    ['<span class="ce-typ">String</span>', 'typename'],
];
let fail = 0;
for (const [needle, label] of checks) {
    const ok = out.includes(needle);
    console.log((ok ? 'PASS' : 'FAIL') + ' - ' + label);
    if (!ok) fail++;
}
if (fail) process.exit(1);
console.log('SYNTAX HIGHLIGHTER SANITY: OK');
