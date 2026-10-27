/* MOPETOT — Cyberpunk city background v2: AERIAL 3D (pure canvas, tanpa dep).
 * Kamera melayang di atas kota (bird view miring ~29 derajat), drift pelan ke depan.
 * - Kota prosedural infinite (hash grid): rooftop, jendela glow, antena beacon
 * - Painter's algorithm: baris jauh -> dekat, cull frustum + depth fog
 * - Hujan 3D: tetes jatuh + RIAK (ripple) di aspal & atap — rintikan terlihat
 * - Petir: strike + flash — saat flash skyline tersorot & fog terangkat
 * - prefers-reduced-motion: render statis sekali
 */
(function () {
    var prefersReduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var canvas = document.createElement('canvas');
    canvas.id = 'city-bg';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.appendChild(canvas);
    var ctx = canvas.getContext('2d');

    // ---------- konstanta tuning ----------
    var PITCH = 0.50;               // sudut pandang ke bawah (rad)
    var CAM_H = 170;                // tinggi kamera (unit dunia)
    var CELL = 34;                  // ukuran satu grid blok
    var DRIFT = 7.0;                 // kecepatan kamera maju (unit/detik)
    var NEAR = 26, FAR = 950;       // depth fog; gedung > 820 tidak digambar (haze)
    var MAX_WINDOWS = 550;          // cap jendela tergambar per frame
    var RAIN_N = 210, RIPPLE_N = 130;

    var W = 0, H = 0, dpr = 1, cx = 0, cy = 0, focal = 0, horizonY = 0;
    var cam = { x: 0, z: 0 };
    var rain = [], ripples = [];
    var flash = 0, bolt = null;
    var nextStrike = performance.now() + 5000;
    var lastT = 0;

    var rand = function (a, b) { return a + Math.random() * (b - a); };
    var sinP = Math.sin(PITCH), cosP = Math.cos(PITCH), tanP = Math.tan(PITCH);

    // ---------- hash deterministik (kota infinite & konsisten) ----------
    function hash(i, j, s) {
        var n = (i * 374761393 + j * 668265263 + s * 1442695041) | 0;
        n = (n ^ (n >>> 13)) * 1274126177 | 0;
        return ((n ^ (n >>> 16)) >>> 0) / 4294967295;
    }

    // ---------- proyeksi 3D -> 2D ----------
    // forward = (0,-sinP,cosP), up = (0,cosP,sinP)
    function proj(x, y, z) {
        var dx = x - cam.x, dy = y - CAM_H, dz = z - cam.z;
        var fz = -dy * sinP + dz * cosP;
        if (fz < NEAR) return null;
        var fy = dy * cosP + dz * sinP;
        var s = focal / fz;
        return [cx + dx * s, cy - fy * s, fz, s];
    }

    // ---------- entitas kota ----------
    function buildingAt(i, j) {
        var h1 = hash(i, j, 1);
        if (h1 < 0.24) return null;                       // 24% cell = jalan/kosong
        var bh = 12 + Math.pow(hash(i, j, 2), 2.4) * 62;  // tinggi (skew: banyak rendah)
        return {
            i: i, j: j,
            x: i * CELL + (hash(i, j, 3) - 0.5) * 6,
            z: j * CELL,
            w: CELL * (0.42 + hash(i, j, 4) * 0.28),
            d: CELL * (0.42 + hash(i, j, 5) * 0.28),
            h: bh,
            hue: hash(i, j, 6),
            winSeed: hash(i, j, 7),
            ant: hash(i, j, 8) < 0.30,
            roofBox: hash(i, j, 9) < 0.5
        };
    }

    var cellCache = new Map();
    function cell(i, j) {
        var k = i + ',' + j;
        var b = cellCache.get(k);
        if (b === undefined) {
            b = buildingAt(i, j);
            if (cellCache.size > 9000) cellCache.clear();
            cellCache.set(k, b);
        }
        return b;
    }

    // ---------- warna helper ----------
    function fogged(r, g, b, depth) {
        var f = Math.min(1, depth / FAR);
        f = f * f * 0.85;
        return 'rgb(' + ((r * (1 - f) + 12 * f) | 0) + ',' + ((g * (1 - f) + 6 * f) | 0) + ',' + ((b * (1 - f) + 30 * f) | 0) + ')';
    }

    function quad(p1, p2, p3, p4, fill) {
        if (!p1 || !p2 || !p3 || !p4) return;
        ctx.fillStyle = fill;
        ctx.beginPath();
        ctx.moveTo(p1[0], p1[1]);
        ctx.lineTo(p2[0], p2[1]);
        ctx.lineTo(p3[0], p3[1]);
        ctx.lineTo(p4[0], p4[1]);
        ctx.closePath();
        ctx.fill();
    }

    var winCount = 0;

    function drawBuilding(b, lit) {
        // ---- LOD bertingkat: proyeksi kasar dulu ----
        var pT = proj(b.x, b.h, b.z);
        var pB = proj(b.x, 0, b.z);
        if (!pT || !pB) return;
        var fz = pB[2];
        if (fz > 820) return;                            // terlalu jauh: serah ke haze
        // jauh: tipiskan density (perbedaan tak terlihat di balik haze)
        if (fz > 700 && hash(b.i, b.j, 11) < 0.55) return;
        var scale = pB[3];

        // tier 1: jauh -> kolom siluet sederhana (1 draw call)
        if (fz > 500) {
            ctx.fillStyle = fogged(20, 10, 40, fz);
            ctx.fillRect(pT[0] - 1, pT[1], 2, Math.max(1.4, pB[1] - pT[1]));
            return;
        }

        var x0 = b.x - b.w / 2, x1 = b.x + b.w / 2;
        var z0 = b.z - b.d / 2, z1 = b.z + b.d / 2;
        var top = b.h;

        // 4 sudut bawah + 4 sudut atas
        var b1 = proj(x0, 0, z1), b2 = proj(x1, 0, z1);       // sisi depan (menghadap kamera)
        var b3 = proj(x1, 0, z0), b4 = proj(x0, 0, z0);
        var t1 = proj(x0, top, z1), t2 = proj(x1, top, z1);
        var t3 = proj(x1, top, z0), t4 = proj(x0, top, z0);
        if (!t1 && !t2 && !t3 && !t4) return;

        var depth = (b1 || t1 || b2)[2];
        var boost = 1 + flash * 0.9;

        // warna dasar per hue gedung
        var base = 16 + b.hue * 10;
        var r = base, g = base * 0.45, bl = base * 1.9;

        // TOP face (rooftop — terlihat dari atas)
        var roof = fogged(r * 1.7 * boost, g * 1.5 * boost, bl * 1.5 * boost, depth);
        quad(t1, t2, t3, t4, roof);

        // FRONT face (z1) — selalu menghadap kamera
        var wallF = fogged(r * boost, g * boost, bl * boost, depth);
        quad(b1, b2, t2, t1, wallF);

        // SIDE face: hanya untuk gedung dekat (fz < 380) — di kejauhan tak terlihat
        if (fz < 380 && b.x > cam.x) {
            quad(b1, b4, t4, t1, fogged(r * 0.7 * boost, g * 0.7 * boost, bl * 0.7 * boost, depth));
        } else if (fz < 380) {
            quad(b2, b3, t3, t2, fogged(r * 0.7 * boost, g * 0.7 * boost, bl * 0.7 * boost, depth));
        }

        // jendela glow (hanya gedung cukup dekat, sesuai cap)
        if (depth < 620 && winCount < MAX_WINDOWS) {
            var cols = 3 + ((b.winSeed * 4) | 0);
            var rowsN = Math.max(2, (b.h / 12) | 0);
            var cw = b.w / (cols + 1), rh = 9;
            for (var wy = 6; wy < top - 5; wy += rh) {
                for (var wi = 0; wi < cols; wi++) {
                    var wseed = hash(b.i * 31 + wi, b.j * 17 + ((wy / rh) | 0), 42);
                    if (wseed < 0.34) {
                        var wx = x0 + cw * (wi + 0.9);
                        var p = proj(wx, wy, z1);
                        if (p && p[0] > -20 && p[0] < W + 20) {
                            var size = Math.max(0.8, 2.6 * p[3]);
                            var colors = ['#00f0ff', '#ff00ea', '#fcee0a', '#7db2f8'];
                            ctx.globalAlpha = Math.min(1, (0.16 + wseed * 0.22) + flash * 0.6);
                            ctx.fillStyle = colors[(wseed * 4) | 0];
                            ctx.fillRect(p[0], p[1], size, size * 1.3);
                            winCount++;
                            if (winCount >= MAX_WINDOWS) break;
                        }
                    }
                }
            }
            ctx.globalAlpha = 1;
        }

        // antena + beacon di rooftop (hanya dekat)
        if (b.ant && fz < 300) {
            var ax = b.x + (b.w * 0.3) * (b.hue < 0.5 ? 1 : -1);
            var ay = top + 10;
            var pb = proj(ax, top, b.z);
            var pt = proj(ax, ay, b.z);
            if (pb && pt) {
                ctx.strokeStyle = fogged(60, 40, 90, depth);
                ctx.lineWidth = Math.max(0.6, 1.2 * pb[3]);
                ctx.beginPath();
                ctx.moveTo(pb[0], pb[1]);
                ctx.lineTo(pt[0], pt[1]);
                ctx.stroke();
                // beacon merah berkedip
                var bl2 = 0.2 + 0.8 * Math.abs(Math.sin(performance.now() * 0.002 + b.hue * 6.28));
                ctx.fillStyle = '#ff2b4d';
                ctx.globalAlpha = Math.min(1, bl2 * 0.55 + flash * 0.4);
                ctx.fillRect(pt[0] - 1, pt[1] - 1, 2.2, 2.2);
                ctx.globalAlpha = 1;
            }
        }
        // kotak AC di atap (hanya dekat)
        if (b.roofBox && fz < 240) {
            var q1 = proj(b.x - 4, top + 3, b.z + 3), q2 = proj(b.x + 4, top + 3, b.z + 3);
            var q3 = proj(b.x + 4, top + 3, b.z - 3), q4 = proj(b.x - 4, top + 3, b.z - 3);
            quad(q1, q2, q3, q4, fogged(24, 12, 46, depth));
        }
    }

    // ---------- ground: aspal basah + glow jalanan ----------
    function drawGround() {
        // base gelap dari horizon ke bawah
        ctx.fillStyle = '#070310';
        ctx.fillRect(0, Math.max(0, horizonY), W, H - Math.max(0, horizonY));
        // strip glow jalanan (basah, pantulan neon samar)
        var j0 = Math.floor(cam.z / (CELL * 4));
        for (var k = 0; k < 14; k++) {
            var j = (j0 + k) * CELL * 4;
            var pL = proj(cam.x - 4000, 0, j), pR = proj(cam.x + 4000, 0, j);
            if (!pL || !pR) continue;
            var depth = pL[2];
            var alpha = Math.max(0, 0.05 * (1 - depth / FAR)) + flash * 0.05;
            if (alpha <= 0.004) continue;
            var col = (j / (CELL * 4)) % 2 === 0 ? '0,240,255' : '255,0,234';
            ctx.strokeStyle = 'rgba(' + col + ',' + alpha.toFixed(3) + ')';
            ctx.lineWidth = 1.4;
            ctx.beginPath();
            ctx.moveTo(pL[0], pL[1]);
            ctx.lineTo(pR[0], pR[1]);
            ctx.stroke();
        }
    }

    // ---------- hujan: tetes 3D + rintikan (ripple) ----------
    function initRain() {
        rain = [];
        for (var i = 0; i < RAIN_N; i++) {
            rain.push({
                x: rand(-500, 500), z: rand(30, 700), y: rand(0, CAM_H + 160),
                v: rand(150, 240), len: rand(5, 11)
            });
        }
        ripples = [];
    }

    function spawnRipple(x, z) {
        // cek apakah jatuh di atap gedung
        var i = Math.round(x / CELL), j = Math.round(z / CELL);
        var b = cell(i, j);
        var y = 0;
        if (b && Math.abs(x - b.x) < b.w / 2 && Math.abs(z - b.z) < b.d / 2) {
            y = b.h;
        }
        if (ripples.length >= RIPPLE_N) ripples.shift();
        ripples.push({ x: x, y: y, z: z, r: 0.5, a: 0.5 });
    }

    function drawRain(dt) {
        ctx.strokeStyle = 'rgba(150,180,240,1)';
        ctx.lineWidth = 1;
        for (var i = 0; i < rain.length; i++) {
            var d = rain[i];
            var p1 = proj(cam.x + d.x, d.y, cam.z + d.z);
            var p2 = proj(cam.x + d.x, d.y + d.len, cam.z + d.z);
            d.y -= d.v * dt;
            if (d.y <= 0) {
                spawnRipple(cam.x + d.x, cam.z + d.z);
                d.y = CAM_H + rand(20, 120);
                d.x = rand(-500, 500);
                d.z = rand(30, 700);
                continue;
            }
            if (!p1 || !p2) {
                if (d.z < 30) d.z = rand(30, 700);
                continue;
            }
            var depth = p1[2];
            var alpha = Math.max(0.04, 0.30 - depth * 0.0004) + flash * 0.12;
            ctx.globalAlpha = Math.min(0.6, alpha);
            ctx.beginPath();
            ctx.moveTo(p1[0], p1[1]);
            ctx.lineTo(p2[0], p2[1]);
            ctx.stroke();
        }
        ctx.globalAlpha = 1;

        // rintikan: ellipse membesar & memudar
        for (var r = ripples.length - 1; r >= 0; r--) {
            var rp = ripples[r];
            rp.r += 26 * dt;
            rp.a -= 1.4 * dt;
            if (rp.a <= 0) { ripples.splice(r, 1); continue; }
            var p = proj(rp.x, rp.y, rp.z);
            if (!p) continue;
            var rx = rp.r * p[3];
            if (rx < 0.8) continue;
            var ry = rx * 0.38;
            ctx.strokeStyle = 'rgba(160,200,255,' + (rp.a * 0.55).toFixed(3) + ')';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.ellipse(p[0], p[1], rx, ry, 0, 0, 6.283);
            ctx.stroke();
        }
    }

    // ---------- petir ----------
    function makeBolt() {
        var x0 = rand(W * 0.1, W * 0.9);
        var y0 = horizonY - rand(10, 60);
        var yEnd = horizonY + rand(30, 90);
        var pts = [[x0, y0]];
        var x = x0, y = y0;
        var segs = 6 + (Math.random() * 4 | 0);
        for (var i = 0; i < segs; i++) {
            y += (yEnd - y0) / segs;
            x += rand(-18, 18);
            pts.push([x, y]);
        }
        return { pts: pts, life: 1 };
    }

    function drawBolt() {
        if (!bolt) return;
        ctx.save();
        ctx.globalCompositeOperation = 'lighter';
        ctx.strokeStyle = 'rgba(225,235,255,' + (bolt.life * 0.9).toFixed(3) + ')';
        ctx.lineWidth = 2.2;
        ctx.shadowColor = 'rgba(160,120,255,0.9)';
        ctx.shadowBlur = 16;
        ctx.beginPath();
        ctx.moveTo(bolt.pts[0][0], bolt.pts[0][1]);
        for (var i = 1; i < bolt.pts.length; i++) ctx.lineTo(bolt.pts[i][0], bolt.pts[i][1]);
        ctx.stroke();
        ctx.restore();
        bolt.life -= 0.06;
        if (bolt.life <= 0) bolt = null;
    }

    // ---------- frame ----------
    function drawSky() {
        var g = ctx.createLinearGradient(0, 0, 0, H);
        g.addColorStop(0, '#030108');
        g.addColorStop(Math.max(0.05, horizonY / H - 0.02), '#08041a');
        g.addColorStop(Math.min(1, horizonY / H + 0.25), '#0d0524');
        g.addColorStop(1, '#050209');
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, W, H);
        // glow kota di awan saat flash
        if (flash > 0.01) {
            var g2 = ctx.createLinearGradient(0, horizonY - H * 0.25, 0, horizonY + H * 0.1);
            g2.addColorStop(0, 'rgba(120,60,220,0)');
            g2.addColorStop(1, 'rgba(150,80,240,' + (flash * 0.28).toFixed(3) + ')');
            ctx.fillStyle = g2;
            ctx.fillRect(0, horizonY - H * 0.25, W, H * 0.35 + 10);
            ctx.fillStyle = 'rgba(180,150,255,' + (flash * 0.06).toFixed(3) + ')';
            ctx.fillRect(0, 0, W, H);
        }
    }

    function drawCityRows() {
        winCount = 0;
        var jNear = Math.floor((cam.z - CELL * 2) / CELL);
        var jFar = Math.floor((cam.z + FAR) / CELL);
        for (var j = jFar; j >= jNear; j--) {           // jauh -> dekat (painter)
            var rowZ = j * CELL;
            var dz = rowZ - cam.z;
            if (dz < -CELL) continue;
            var ptest = proj(cam.x, 0, rowZ);
            if (!ptest) continue;
            if (ptest[2] > FAR) continue;               // cull baris terlalu jauh
            if (ptest[1] < -80) continue;               // baris di bawah layar
            var depth = Math.max(NEAR, ptest[2]);
            var span = (W * 0.75) * depth / focal + CELL * 3;
            var i0 = Math.floor((cam.x - span) / CELL);
            var i1 = Math.ceil((cam.x + span) / CELL);
            if (i1 - i0 > 60) { i1 = i0 + 60; }        // guard perf
            for (var i = i0; i <= i1; i++) {
                var b = cell(i, j);
                if (b) drawBuilding(b, 1);
            }
        }
    }

    function frame(now) {
        var dt = Math.min(0.05, (now - lastT) / 1000 || 0.016);
        lastT = now;

        // gerak kamera: maju pelan + sway samping lembut
        cam.z += DRIFT * dt;
        cam.x = Math.sin(now * 0.00007) * 90 + Math.sin(now * 0.00013) * 40;

        // jadwal petir
        if (now >= nextStrike) {
            bolt = makeBolt();
            flash = 1;
            if (Math.random() < 0.6) {
                setTimeout(function () { flash = Math.max(flash, 0.85); }, 90 + Math.random() * 130);
            }
            nextStrike = now + rand(6000, 16000);
        }
        flash *= 0.94;
        if (flash < 0.005) flash = 0;

        drawSky();
        drawGround();
        drawCityRows();
        drawRain(dt);
        drawBolt();
        requestAnimationFrame(frame);
    }

    function resize() {
        dpr = Math.min(window.devicePixelRatio || 1, 1.35);
        W = window.innerWidth;
        H = window.innerHeight;
        canvas.width = Math.max(1, W * dpr);
        canvas.height = Math.max(1, H * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        cx = W / 2;
        cy = H / 2;
        focal = H * 0.37;                 // hasil tuning: horizon ~30% dari atas
        horizonY = cy - focal * tanP;
        initRain();
        if (prefersReduced) {
            drawSky();
            drawGround();
            drawCityRows();
            drawRain(0);
        }
    }

    window.addEventListener('resize', function () {
        clearTimeout(window.__cityResize);
        window.__cityResize = setTimeout(resize, 150);
    });
    resize();
    if (!prefersReduced) {
        requestAnimationFrame(frame);
    }
})();
