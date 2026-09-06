/*
  hero-decode.js
  --------------
  Animates any element with class "decode-text" so its final text appears
  to "resolve" out of scrambled characters - like a system scanning and
  identifying a signal. Fits the IDS theme (detection = resolving signal
  from noise) rather than being decoration for its own sake.

  Usage: <h1 class="decode-text" data-text="IntelliSense"></h1>
*/

(function () {
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ01#$%&';

  document.querySelectorAll('.decode-text').forEach(el => {
    const finalText = el.dataset.text || el.textContent;
    const duration = 900; // ms
    const startTime = performance.now();

    function frame(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const revealCount = Math.floor(progress * finalText.length);

      let out = '';
      for (let i = 0; i < finalText.length; i++) {
        if (finalText[i] === ' ') { out += ' '; continue; }
        if (i < revealCount) {
          out += finalText[i];
        } else {
          out += CHARS[Math.floor(Math.random() * CHARS.length)];
        }
      }
      el.textContent = out;

      if (progress < 1) {
        requestAnimationFrame(frame);
      } else {
        el.textContent = finalText;
      }
    }
    requestAnimationFrame(frame);
  });
})();
