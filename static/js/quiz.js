// quiz.js
// -------
// Generic quiz-taking UI, shared by:
//   - Post-simulation quizzes (simulator.js calls this after a run)
//   - Learning Module quizzes (module_detail.html calls this directly)
//
// Usage:
//   IntelliQuiz.render(containerEl, questions, {
//       itemType: 'simulation' | 'module',
//       itemKey: 'port_scan',
//       onComplete: (score, total) => { ... }
//   });

const IntelliQuiz = (function () {

    function render(container, questions, opts) {
        if (!questions || questions.length === 0) {
            container.innerHTML = `<p style="color:var(--muted);">No quiz available for this yet.</p>`;
            return;
        }

        const answers = new Array(questions.length).fill(null);

        container.innerHTML = `
            <div class="quiz-box">
                ${questions.map((q, qi) => `
                    <div class="quiz-question" data-qi="${qi}">
                        <p class="quiz-question-text">${qi + 1}. ${q.question}</p>
                        <div class="quiz-options">
                            ${q.options.map((opt, oi) => `
                                <label class="quiz-option">
                                    <input type="radio" name="q${qi}" value="${oi}">
                                    <span>${opt}</span>
                                </label>
                            `).join('')}
                        </div>
                        <div class="quiz-explanation" style="display:none;"></div>
                    </div>
                `).join('')}
                <button class="quiz-submit-btn">Submit Answers</button>
                <div class="quiz-result" style="display:none;"></div>
            </div>
        `;

        container.querySelectorAll('input[type="radio"]').forEach(input => {
            input.addEventListener('change', (e) => {
                const qi = parseInt(e.target.closest('.quiz-question').dataset.qi);
                answers[qi] = parseInt(e.target.value);
            });
        });

        container.querySelector('.quiz-submit-btn').addEventListener('click', () => {
            submit(container, questions, answers, opts);
        });
    }

    function submit(container, questions, answers, opts) {
        if (answers.includes(null)) {
            alert('Please answer every question before submitting.');
            return;
        }

        let score = 0;
        const results = []; // {correct: bool, questionText: str}

        questions.forEach((q, qi) => {
            const qEl = container.querySelector(`.quiz-question[data-qi="${qi}"]`);
            const correct = answers[qi] === q.correct;
            if (correct) score++;
            results.push({ correct, questionText: q.question });

            const options = qEl.querySelectorAll('.quiz-option');
            options.forEach((optEl, oi) => {
                optEl.classList.add('locked');
                if (oi === q.correct) optEl.classList.add('correct');
                else if (oi === answers[qi]) optEl.classList.add('incorrect');
            });

            const expEl = qEl.querySelector('.quiz-explanation');
            expEl.style.display = 'block';
            expEl.innerHTML = `<strong>${correct ? '✅ Correct.' : '❌ Not quite.'}</strong> ${q.explanation}`;
        });

        container.querySelector('.quiz-submit-btn').style.display = 'none';

        const resultEl = container.querySelector('.quiz-result');
        resultEl.style.display = 'block';
        resultEl.innerHTML = `<strong>Score: ${score} / ${questions.length}</strong>`;

        // --- Analysis: a qualitative headline + a per-question review list,
        // so the student sees not just a number but WHAT to go back and review ---
        const pct = Math.round((score / questions.length) * 100);
        let headlineClass, headlineText;
        if (pct >= 80) {
            headlineClass = 'excellent';
            headlineText = '🌟 Excellent understanding of this material.';
        } else if (pct >= 50) {
            headlineClass = 'good';
            headlineText = '👍 Good start - review the explanations below for the ones you missed.';
        } else {
            headlineClass = 'needs-review';
            headlineText = '📖 Worth another pass - review the material above before moving on.';
        }

        const analysisEl = document.createElement('div');
        analysisEl.className = 'quiz-analysis';
        analysisEl.innerHTML = `
            <div class="qa-headline ${headlineClass}">${headlineText}</div>
            <ul>
                ${results.map(r => `
                    <li>
                        <span class="qa-icon">${r.correct ? '✅' : '❌'}</span>
                        <span>${r.questionText}</span>
                    </li>
                `).join('')}
            </ul>
        `;
        resultEl.after(analysisEl);

        if (opts && opts.itemType && opts.itemKey) {
            fetch('/api/progress/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    item_type: opts.itemType,
                    item_key: opts.itemKey,
                    score: score,
                    total: questions.length
                })
            }).catch(err => console.error('Failed to record progress:', err));
        }

        if (opts && typeof opts.onComplete === 'function') {
            opts.onComplete(score, questions.length);
        }
    }

    return { render };
})();