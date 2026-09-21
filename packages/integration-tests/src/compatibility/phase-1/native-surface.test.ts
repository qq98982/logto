import {
  assertCandidateNativeSurfaceValue,
  asterNativeSurfaceContract,
  nativeSurfaceValue,
  projectNativeSurfaceObservation,
  projectOracleNativeSurfaceValue,
} from './native-surface.js';
import type { Phase1Profile } from './profile-types.js';

const profile = (): Phase1Profile =>
  ({
    schemaVersion: 2,
    asterNativeSurface: structuredClone(asterNativeSurfaceContract),
  }) as unknown as Phase1Profile;

describe('Aster native surface projection', () => {
  it('resolves target values from the closed profile contract', () => {
    const value = profile();

    expect(nativeSurfaceValue(value, 'oracle', 'applicationIdHeader')).toBe('logto-app-id');
    expect(nativeSurfaceValue(value, 'candidate', 'applicationIdHeader')).toBe('aster-app-id');
    expect(nativeSurfaceValue(value, 'oracle', 'sessionScope')).toBe('urn:logto:scope:sessions');
    expect(nativeSurfaceValue(value, 'candidate', 'sessionScope')).toBe('urn:aster:scope:sessions');
  });

  it('projects only complete exact and prefix reference values', () => {
    const value = profile();

    expect(projectOracleNativeSurfaceValue(value, 'sharedExperienceCookie', '_logto')).toBe(
      '_aster'
    );
    expect(
      projectOracleNativeSurfaceValue(
        value,
        'organizationAudiencePrefix',
        'urn:logto:organization:t-default'
      )
    ).toBe('urn:aster:organization:t-default');
    expect(() =>
      projectOracleNativeSurfaceValue(value, 'sharedExperienceCookie', '_logto_extra')
    ).toThrow('Invalid Phase 1 oracle native surface');
    expect(() =>
      projectOracleNativeSurfaceValue(
        value,
        'organizationAudiencePrefix',
        'xurn:logto:organization:t'
      )
    ).toThrow('Invalid Phase 1 oracle native surface');
  });

  it('accepts only the candidate form and never normalizes a candidate legacy marker', () => {
    const value = profile();

    expect(() => {
      assertCandidateNativeSurfaceValue(value, 'requestIdHeader', 'aster-core-request-id');
    }).not.toThrow();
    expect(() => {
      assertCandidateNativeSurfaceValue(value, 'generatedCookiePrefix', '_aster_session');
    }).not.toThrow();
    expect(() => {
      assertCandidateNativeSurfaceValue(value, 'requestIdHeader', 'logto-core-request-id');
    }).toThrow('Invalid Phase 1 candidate native surface');
    expect(() => {
      assertCandidateNativeSurfaceValue(value, 'generatedCookiePrefix', '_logto_session');
    }).toThrow('Invalid Phase 1 candidate native surface');
    expect(() => {
      assertCandidateNativeSurfaceValue(value, 'sessionScope', 'urn:aster:scope:sessions');
    }).not.toThrow();
    expect(() => {
      assertCandidateNativeSurfaceValue(value, 'sessionScope', 'urn:logto:scope:sessions');
    }).toThrow('Invalid Phase 1 candidate native surface');
  });

  it('projects canonical observation fields without requiring a profile instance', () => {
    expect(
      projectNativeSurfaceObservation(
        'oracle',
        'organizationAudiencePrefix',
        'urn:logto:organization:t-default'
      )
    ).toBe('urn:aster:organization:t-default');
    expect(
      projectNativeSurfaceObservation(
        'candidate',
        'organizationAudiencePrefix',
        'urn:aster:organization:t-default'
      )
    ).toBe('urn:aster:organization:t-default');
    expect(() =>
      projectNativeSurfaceObservation(
        'candidate',
        'organizationAudiencePrefix',
        'urn:logto:organization:t-default'
      )
    ).toThrow('Invalid Phase 1 candidate native surface');
  });

  it('fails closed for unknown marker IDs without exposing the supplied value', () => {
    const sentinel = 'private-marker-sentinel';

    expect(() =>
      nativeSurfaceValue(
        profile(),
        'candidate',
        'unknown-marker' as Parameters<typeof nativeSurfaceValue>[2]
      )
    ).toThrow('Invalid Phase 1 native surface marker');
    try {
      projectOracleNativeSurfaceValue(profile(), 'productName', sentinel);
    } catch (error: unknown) {
      expect(String(error)).not.toContain(sentinel);
    }
  });
});
