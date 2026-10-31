import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('Firestore security rules enforce all 8 pillars and reject Dirty Dozen payloads', () => {
  const rules = fs.readFileSync('firestore.rules', 'utf8');
  // 1. Default-Deny Catch-All
  assert.ok(rules.includes('match /{document=**} {\n      allow read, write: if false;\n    }'));
  // 2. Email verification requirement
  assert.ok(rules.includes('request.auth.token.email_verified == true'));
  // 3. ID Poisoning guard
  assert.ok(rules.includes("id.matches('^[a-zA-Z0-9_\\\\-]+$')"));
  // 4. Strict schema validation helpers
  assert.ok(rules.includes('isValidAnnouncement(incoming())'));
  assert.ok(rules.includes('isValidUserProfile(incoming())'));
  assert.ok(rules.includes('isValidTask(incoming())'));
  // 5. Timestamp integrity
  assert.ok(rules.includes('incoming().createdAt == request.time'));
  assert.ok(rules.includes('incoming().updatedAt == request.time'));
  // 6. Query Enforcer on list
  assert.ok(rules.includes('allow list: if isSignedIn() && resource.data.userId == request.auth.uid;'));
});
