/** Pure chart helpers (the rendering itself is verified in the browser). */

import { describe, expect, it } from 'vitest';

// The dashboard frontend is plain ES modules, so its pure helpers are testable
// directly. Nothing here touches the DOM.
// @ts-expect-error - untyped browser module
import { labelIndices } from '../public/js/charts.js';

describe('axis label placement', () => {
  it('labels every point when there are few of them', () => {
    expect(labelIndices(0)).toEqual([]);
    expect(labelIndices(1)).toEqual([0]);
    expect(labelIndices(5)).toEqual([0, 1, 2, 3, 4]);
  });

  it('thins labels to roughly eight ticks', () => {
    expect(labelIndices(30).length).toBeLessThanOrEqual(9);
    expect(labelIndices(90).length).toBeLessThanOrEqual(9);
  });

  it('always labels the final point', () => {
    for (const count of [9, 12, 14, 30, 60, 90]) {
      expect(labelIndices(count).at(-1)).toBe(count - 1);
    }
  });

  it('never places the final label on top of the previous one', () => {
    for (const count of [9, 12, 13, 14, 30, 45, 60, 90, 92]) {
      const indices = labelIndices(count);
      const step = Math.ceil(count / 8);
      const gap = indices.at(-1)! - indices.at(-2)!;
      expect(gap, `count=${count} produced a ${gap}-wide final gap`).toBeGreaterThanOrEqual(step);
    }
  });

  it('starts at the first point and stays ascending', () => {
    for (const count of [9, 30, 90]) {
      const indices = labelIndices(count);
      expect(indices[0]).toBe(0);
      for (let index = 1; index < indices.length; index += 1) {
        expect(indices[index]).toBeGreaterThan(indices[index - 1]);
      }
    }
  });
});
