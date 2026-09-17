/** Minimal dependency-free SVG charts. */

import { el, money, number } from './ui.js';

const NS = 'http://www.w3.org/2000/svg';

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null) continue;
    node.setAttribute(key, String(value));
  }
  return node;
}

/**
 * Bar chart for a time series.
 * `points`: [{ label, value, title }]
 */
export function barChart(points, options = {}) {
  const width = options.width ?? 720;
  const height = options.height ?? 180;
  const padding = { top: 8, right: 8, bottom: 22, left: 8 };
  const svg = svgEl('svg', {
    class: 'chart',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': options.ariaLabel ?? 'Bar chart',
    preserveAspectRatio: 'none',
  });

  if (!points.length) return svg;

  const max = Math.max(...points.map((point) => point.value), 0.0001);
  const plotHeight = height - padding.top - padding.bottom;
  const slot = (width - padding.left - padding.right) / points.length;
  const barWidth = Math.max(1, slot * 0.72);

  points.forEach((point, index) => {
    const barHeight = Math.max(1, (point.value / max) * plotHeight);
    const x = padding.left + index * slot + (slot - barWidth) / 2;
    const y = padding.top + plotHeight - barHeight;
    const rect = svgEl('rect', {
      class: point.muted ? 'chart__bar chart__bar--muted' : 'chart__bar',
      x,
      y,
      width: barWidth,
      height: barHeight,
      rx: Math.min(2, barWidth / 3),
    });
    rect.append(svgEl('title')).textContent = point.title ?? `${point.label}: ${point.value}`;
    svg.append(rect);
  });

  svg.append(
    svgEl('line', {
      class: 'chart__axis',
      x1: padding.left,
      y1: padding.top + plotHeight,
      x2: width - padding.right,
      y2: padding.top + plotHeight,
    })
  );

  const labelEvery = Math.ceil(points.length / 8);
  points.forEach((point, index) => {
    if (index % labelEvery !== 0 && index !== points.length - 1) return;
    const text = svgEl('text', {
      class: 'chart__label',
      x: padding.left + index * slot + slot / 2,
      y: height - 6,
      'text-anchor': 'middle',
    });
    text.textContent = point.label;
    svg.append(text);
  });

  return svg;
}

/** Line chart with a filled area. */
export function lineChart(points, options = {}) {
  const width = options.width ?? 720;
  const height = options.height ?? 180;
  const padding = { top: 10, right: 8, bottom: 22, left: 8 };
  const svg = svgEl('svg', {
    class: 'chart',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': options.ariaLabel ?? 'Line chart',
    preserveAspectRatio: 'none',
  });
  if (points.length < 2) return barChart(points, options);

  const max = Math.max(...points.map((point) => point.value), 0.0001);
  const plotHeight = height - padding.top - padding.bottom;
  const step = (width - padding.left - padding.right) / (points.length - 1);

  const coords = points.map((point, index) => ({
    x: padding.left + index * step,
    y: padding.top + plotHeight - (point.value / max) * plotHeight,
  }));

  const path = coords
    .map((coord, index) => `${index === 0 ? 'M' : 'L'}${coord.x},${coord.y}`)
    .join(' ');
  const area = `${path} L${coords[coords.length - 1].x},${padding.top + plotHeight} L${coords[0].x},${
    padding.top + plotHeight
  } Z`;

  svg.append(svgEl('path', { class: 'chart__area', d: area }));
  svg.append(svgEl('path', { class: 'chart__line', d: path }));
  svg.append(
    svgEl('line', {
      class: 'chart__axis',
      x1: padding.left,
      y1: padding.top + plotHeight,
      x2: width - padding.right,
      y2: padding.top + plotHeight,
    })
  );

  points.forEach((point, index) => {
    const circle = svgEl('circle', {
      cx: coords[index].x,
      cy: coords[index].y,
      r: 6,
      fill: 'transparent',
    });
    circle.append(svgEl('title')).textContent = point.title ?? `${point.label}: ${point.value}`;
    svg.append(circle);
  });

  const labelEvery = Math.ceil(points.length / 8);
  points.forEach((point, index) => {
    if (index % labelEvery !== 0 && index !== points.length - 1) return;
    const text = svgEl('text', {
      class: 'chart__label',
      x: coords[index].x,
      y: height - 6,
      'text-anchor': index === 0 ? 'start' : index === points.length - 1 ? 'end' : 'middle',
    });
    text.textContent = point.label;
    svg.append(text);
  });

  return svg;
}

/** Horizontal breakdown bars, used for service and region splits. */
export function breakdownBars(rows, options = {}) {
  const max = Math.max(...rows.map((row) => Math.abs(row.value)), 0.0001);
  return el(
    'div',
    { class: 'stack' },
    rows.map((row) => {
      const width = `${Math.max(1, (Math.abs(row.value) / max) * 100)}%`;
      return el('div', {}, [
        el('div', { class: 'flex-between' }, [
          el('span', { class: 'truncate', title: row.label, text: row.label }),
          el('span', {
            class: 'mono nowrap',
            text: options.currency ? money(row.value, options.currency) : number(row.value),
          }),
        ]),
        el(
          'div',
          { style: 'background:var(--surface-3);border-radius:4px;height:6px;overflow:hidden' },
          el('div', {
            style: `width:${width};height:100%;background:${row.color ?? 'var(--accent)'}`,
          })
        ),
      ]);
    })
  );
}
