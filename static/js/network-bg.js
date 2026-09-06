/*
  network-bg.js
  -------------
  Draws an animated network graph on a full-screen canvas:
  - Nodes drift slowly and connect to nearby nodes with faint lines
  - "Packets" (small glowing dots) travel along those connections

  This is a deliberate design choice, not decoration: IntelliSense is a
  network intrusion detection tool, so the background literally represents
  packets moving across a monitored network - the same thing the dashboard
  visualizes with real data.

  Usage: include this script + <canvas id="bg-canvas"></canvas> in a page.
*/

(function () {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let width, height;
  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resize);
  resize();

  const NODE_COUNT = Math.min(55, Math.floor((width * height) / 22000));
  const CONNECT_DIST = 150;
  const colors = ['#3b82f6', '#8b5cf6', '#06b6d4', '#22c55e'];

  const nodes = Array.from({ length: NODE_COUNT }, () => ({
    x: Math.random() * width,
    y: Math.random() * height,
    vx: (Math.random() - 0.5) * 0.25,
    vy: (Math.random() - 0.5) * 0.25,
    r: Math.random() * 1.5 + 1
  }));

  // Packets: each one travels from one node to a connected node
  const packets = [];
  function spawnPacket() {
    if (nodes.length < 2) return;
    const a = nodes[Math.floor(Math.random() * nodes.length)];
    const b = nodes[Math.floor(Math.random() * nodes.length)];
    if (a === b) return;
    packets.push({
      from: a, to: b, t: 0,
      speed: 0.004 + Math.random() * 0.006,
      color: colors[Math.floor(Math.random() * colors.length)]
    });
  }
  setInterval(spawnPacket, 300);

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // update + draw nodes
    nodes.forEach(n => {
      n.x += n.vx; n.y += n.vy;
      if (n.x < 0 || n.x > width) n.vx *= -1;
      if (n.y < 0 || n.y > height) n.vy *= -1;

      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(148,163,184,0.55)';
      ctx.fill();
    });

    // draw connections between close nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECT_DIST) {
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.strokeStyle = `rgba(59,130,246,${0.12 * (1 - dist / CONNECT_DIST)})`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      }
    }

    // update + draw packets traveling along their path
    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i];
      p.t += p.speed;
      if (p.t >= 1) { packets.splice(i, 1); continue; }

      const x = p.from.x + (p.to.x - p.from.x) * p.t;
      const y = p.from.y + (p.to.y - p.from.y) * p.t;

      ctx.beginPath();
      ctx.arc(x, y, 2.4, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    requestAnimationFrame(draw);
  }

  // Respect reduced-motion preference: draw one static-ish frame, no animation loop
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (!prefersReducedMotion) {
    draw();
  } else {
    ctx.clearRect(0, 0, width, height);
    nodes.forEach(n => {
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(148,163,184,0.4)';
      ctx.fill();
    });
  }
})();
