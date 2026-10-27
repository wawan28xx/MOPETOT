/* MOPETOT BGM — Night City synthwave loop (static/audio/nightcity-loop.wav)
 * - Auto-start saat user gesture pertama (klik "Jack In" / tombol toggle)
 * - Volume fade in/out halus
 * - Preferensi mute diingat via localStorage
 */
(function () {
    var audio = document.getElementById('bgm');
    var btn = document.getElementById('bgm-toggle');
    var TARGET_VOL = 0.32;
    var fadeTimer = null;

    function muted() {
        try { return localStorage.getItem('mopetot_bgm_muted') === '1'; } catch (e) { return false; }
    }

    function setMuted(m) {
        try { localStorage.setItem('mopetot_bgm_muted', m ? '1' : '0'); } catch (e) {}
    }

    function fadeTo(target, done) {
        if (fadeTimer) clearInterval(fadeTimer);
        fadeTimer = setInterval(function () {
            if (!audio) { clearInterval(fadeTimer); return; }
            var cur = audio.volume;
            var next = cur + (target > cur ? 0.02 : -0.04);
            if ((target > cur && next >= target) || (target < cur && next <= target)) {
                audio.volume = target;
                clearInterval(fadeTimer);
                fadeTimer = null;
                if (done) done();
            } else {
                audio.volume = Math.max(0, Math.min(1, next));
            }
        }, 40);
    }

    function updateBtn() {
        if (!btn) return;
        var playing = audio && !audio.paused && !muted();
        if (playing) {
            btn.classList.add('bgm-playing');
            btn.classList.remove('bgm-muted');
            btn.title = 'Musik Night City — klik untuk mute';
        } else {
            btn.classList.remove('bgm-playing');
            btn.classList.add('bgm-muted');
            btn.title = 'Musik Night City — klik untuk putar';
        }
    }

    window.mpMusicStart = function () {
        if (!audio || muted()) { updateBtn(); return false; }
        var p = audio.play();
        if (p && p.catch) p.catch(function () {});
        audio.volume = 0;
        fadeTo(TARGET_VOL);
        updateBtn();
        return true;
    };

    window.mpToggleMusic = function () {
        if (!audio) return;
        if (!audio.paused) {
            fadeTo(0, function () { audio.pause(); updateBtn(); });
            setMuted(true);
        } else {
            setMuted(false);
            var p = audio.play();
            if (p && p.catch) p.catch(function () {});
            audio.volume = 0;
            fadeTo(TARGET_VOL);
        }
        updateBtn();
    };

    // update ikon saat state berubah dari luar (mis. tab visibilitas)
    if (audio) {
        audio.addEventListener('pause', updateBtn);
        audio.addEventListener('play', updateBtn);
    }
    updateBtn();
})();
