import { describe, it, expect } from 'vitest';
import { haversineDist, calculateBearing, findBestColo, EDGE_TOPOLOGY, interpolateGreatCircle } from '../src/lib/lgpa';

describe('LGPA Algorithm: Geodesic & Arbitration', () => {
  it('haversineDist should calculate realistic distance between coordinates', () => {
    // SFO (37.7697, -122.3933) to LAX (34.0522, -118.2437) is approx 540-560 km
    const sfo = EDGE_TOPOLOGY['SFO'];
    const lax = EDGE_TOPOLOGY['LAX'];
    const dist = haversineDist(sfo.lat, sfo.lng, lax.lat, lax.lng);
    expect(dist).toBeGreaterThan(500);
    expect(dist).toBeLessThan(600);
  });

  it('calculateBearing should compute compass bearings accurately', () => {
    // SFO to LAX is heading roughly South-East (approx 120-150 degrees)
    const sfo = EDGE_TOPOLOGY['SFO'];
    const lax = EDGE_TOPOLOGY['LAX'];
    const bearing = calculateBearing(sfo.lat, sfo.lng, lax.lat, lax.lng);
    expect(bearing).toBeGreaterThan(120);
    expect(bearing).toBeLessThan(150);
  });

  it('findBestColo should identify closest edge point', () => {
    // A client in Silicon Valley (near SJC)
    const sjcResult = findBestColo(37.3382, -121.8863);
    expect(sjcResult.name).toBe('SJC');
    expect(sjcResult.distance).toBeLessThan(5);
  });

  it('findBestColo should arbitrate between nearby candidates based on target trajectory', () => {
    // Point roughly midway between SFO and SJC, heading towards Tokyo (NRT)
    const midLat = 37.5;
    const midLng = -122.1;
    const nrt = EDGE_TOPOLOGY['NRT'];
    const result = findBestColo(midLat, midLng, midLat, midLng, nrt.lat, nrt.lng);
    expect(['SFO', 'SJC']).toContain(result.name);
  });

  describe('interpolateGreatCircle (ALGO-01)', () => {
    it('should return start point at fraction 0 and end point at fraction 1', () => {
      const start: [number, number] = [35.6895, 139.6917]; // Tokyo [lat, lng]
      const end: [number, number] = [37.7697, -122.3933]; // SFO [lat, lng]

      const atZero = interpolateGreatCircle(start[0], start[1], end[0], end[1], 0);
      expect(atZero[0]).toBeCloseTo(start[1], 4);
      expect(atZero[1]).toBeCloseTo(start[0], 4);

      const atOne = interpolateGreatCircle(start[0], start[1], end[0], end[1], 1);
      expect(atOne[0]).toBeCloseTo(end[1], 4);
      expect(atOne[1]).toBeCloseTo(end[0], 4);
    });

    it('should correctly traverse trans-Pacific 180-meridian route without traversing Europe/Africa', () => {
      // Tokyo (35.6895, 139.6917) to SFO (37.7697, -122.3933)
      // Planar linear interpolation yields (139.6917 - 122.3933)/2 = 8.649 deg (Europe/Africa)
      // True Great Circle route traverses North Pacific near Aleutians (approx 48-52 deg N, around -170 to -180 deg)
      const [midLng, midLat] = interpolateGreatCircle(35.6895, 139.6917, 37.7697, -122.3933, 0.5);

      // Must be high latitude North Pacific, NOT Europe/Africa
      expect(midLat).toBeGreaterThan(45);
      expect(midLat).toBeLessThan(55);

      // Longitude should be near the date line in the Pacific, definitely NOT near 8 deg (prime meridian)
      const isNearDateLine = midLng > 160 || midLng < -160;
      expect(isNearDateLine).toBe(true);
      expect(Math.abs(midLng)).toBeGreaterThan(160);
    });

    it('should handle coincident / identical coordinates safely', () => {
      const [lng, lat] = interpolateGreatCircle(40.7128, -74.006, 40.7128, -74.006, 0.5);
      expect(lng).toBeCloseTo(-74.006, 4);
      expect(lat).toBeCloseTo(40.7128, 4);
    });

    it('should clamp out-of-bounds fractions to [0, 1]', () => {
      const atNeg = interpolateGreatCircle(34.05, -118.24, 37.77, -122.42, -0.5);
      expect(atNeg[0]).toBeCloseTo(-118.24, 4);
      expect(atNeg[1]).toBeCloseTo(34.05, 4);

      const atLarge = interpolateGreatCircle(34.05, -118.24, 37.77, -122.42, 1.5);
      expect(atLarge[0]).toBeCloseTo(-122.42, 4);
      expect(atLarge[1]).toBeCloseTo(37.77, 4);
    });
  });
});
