import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { generateKeyPairSync } from 'crypto';
import {
    attestFile,
    generateSigningKey,
    pae,
    signStatement,
    statementFor,
    verifyEnvelope,
} from '../src/attestation';

const sha = (c: string) => c.repeat(40);
const evidence = {
    schemaVersion: 1,
    kind: 'dependency-review',
    status: 'passed',
    revisions: {
        base: { sha: sha('a'), lockfileSha256: 'b'.repeat(64) },
        head: { sha: sha('c'), lockfileSha256: 'd'.repeat(64) },
    },
};

describe('attestations', () => {
    let dir: string;
    beforeEach(() => (dir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-attest-'))));
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('uses the DSSE pre-authentication encoding', () => {
        expect(pae('t', Buffer.from('hello')).toString()).toBe('DSSEv1 1 t 5 hello');
    });

    it('signs evidence and verifies it with the public key, rejecting tampering and other keys', () => {
        const keys = generateSigningKey(dir);
        expect(fs.statSync(keys.privateKey).mode & 0o777).toBe(0o600);
        expect(() => generateSigningKey(dir)).toThrow('refusing to overwrite');
        const file = path.join(dir, 'dependency-review.json');
        fs.writeFileSync(file, JSON.stringify(evidence));
        const envelopePath = attestFile(file, keys.privateKey);
        expect(envelopePath).toBe(path.join(dir, 'dependency-review.intoto.json'));
        const envelope = JSON.parse(fs.readFileSync(envelopePath, 'utf8'));
        const publicKey = fs.readFileSync(keys.publicKey, 'utf8');
        const check = verifyEnvelope(envelope, publicKey);
        expect(check.valid).toBe(true);
        expect(check.statement?.subject.map((s) => s.name)).toEqual([
            'git-commit:base',
            'package-lock.json:base',
            'git-commit:head',
            'package-lock.json:head',
        ]);
        expect(check.statement?.predicateType).toContain('dependency-review');

        const statement = JSON.parse(Buffer.from(envelope.payload, 'base64').toString());
        statement.predicate.status = 'failed';
        const tampered = {
            ...envelope,
            payload: Buffer.from(JSON.stringify(statement)).toString('base64'),
        };
        expect(verifyEnvelope(tampered, publicKey)).toMatchObject({ valid: false });
        const other = generateKeyPairSync('ed25519')
            .publicKey.export({ type: 'spki', format: 'pem' })
            .toString();
        expect(verifyEnvelope(envelope, other).valid).toBe(false);
        expect(verifyEnvelope({ ...envelope, payloadType: 'x' }, publicKey).reason).toContain(
            'payload type'
        );
    });

    it('refuses incomplete evidence and non-Ed25519 keys', () => {
        expect(() => statementFor({ schemaVersion: 1, revisions: {} })).toThrow('not a complete');
        expect(() =>
            statementFor({ schemaVersion: 1, revisions: { head: { sha: 'zz' } } })
        ).toThrow('Invalid head');
        expect(statementFor({ ...evidence, kind: undefined }).predicateType).toContain(
            'dependency-verification'
        );
        const rsa = generateKeyPairSync('rsa', { modulusLength: 1024 })
            .privateKey.export({ type: 'pkcs8', format: 'pem' })
            .toString();
        expect(() => signStatement(statementFor(evidence), rsa)).toThrow('Ed25519');
    });
});
