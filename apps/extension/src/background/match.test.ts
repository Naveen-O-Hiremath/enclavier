import { describe, expect, it } from 'vitest';
import { matchScore, uriMatches } from './match';

describe('autofill URL matching', () => {
  it('matches the same site across subdomains', () => {
    expect(uriMatches('https://accounts.google.com', 'https://mail.google.com/u/0')).toBe(true);
    expect(uriMatches('github.com', 'https://github.com/login')).toBe(true);
  });

  it('respects public suffixes', () => {
    expect(uriMatches('https://shop.example.co.uk', 'https://www.example.co.uk')).toBe(true);
    expect(uriMatches('https://alice.co.uk', 'https://mallory.co.uk')).toBe(false);
    // Private suffixes: different GitHub Pages sites are different owners.
    expect(uriMatches('https://alice.github.io', 'https://mallory.github.io')).toBe(false);
  });

  it('never matches look-alikes or embedded names', () => {
    expect(uriMatches('https://paypal.com', 'https://paypal.com.evil.test/login')).toBe(false);
    expect(uriMatches('https://paypal.com', 'https://evil-paypal.com')).toBe(false);
    expect(uriMatches('https://bank.test', 'https://bank.test@evil.test/')).toBe(false);
  });

  it('refuses https credentials on plain-http pages', () => {
    expect(uriMatches('https://example.com', 'http://example.com/login')).toBe(false);
    expect(uriMatches('http://intranet.example.com', 'https://intranet.example.com')).toBe(true);
  });

  it('requires an exact host and port for IPs and localhost', () => {
    expect(uriMatches('http://localhost:8088', 'http://localhost:8088/vault')).toBe(true);
    expect(uriMatches('http://localhost:8088', 'http://localhost:3000')).toBe(false);
    expect(uriMatches('https://10.0.0.5', 'https://10.0.0.6')).toBe(false);
  });

  it('ignores non-web schemes and ranks exact hosts first', () => {
    expect(uriMatches('javascript:alert(1)', 'https://example.com')).toBe(false);
    expect(uriMatches('https://example.com', 'chrome://settings')).toBe(false);
    expect(matchScore('https://login.example.com', 'https://login.example.com/x')).toBe(2);
    expect(matchScore('https://example.com', 'https://login.example.com/x')).toBe(1);
  });
});
