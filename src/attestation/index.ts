import * as fs from 'fs';
import * as path from 'path';
import {
    createHash,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    KeyObject,
    sign,
    verify,
} from 'crypto';
import { writeJsonAtomic } from '../services/artifacts';

export const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
export const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
export const PREDICATE_TYPES = {
    verification: 'https://warden.hamzaparacha.me/attestation/dependency-verification/v1',
    'dependency-review': 'https://warden.hamzaparacha.me/attestation/dependency-review/v1',
} as const;

export interface Subject {
    name: string;
    digest: Record<string, string>;
}

export interface Statement {
    _type: typeof STATEMENT_TYPE;
    subject: Subject[];
    predicateType: string;
    predicate: unknown;
}

export interface Envelope {
    payloadType: string;
    payload: string;
    signatures: Array<{ keyid: string; sig: string }>;
}

/** DSSE pre-authentication encoding: the exact bytes that are signed. */
export function pae(payloadType: string, payload: Buffer): Buffer {
    const type = Buffer.from(payloadType, 'utf8');
    return Buffer.concat([
        Buffer.from(`DSSEv1 ${type.length} `),
        type,
        Buffer.from(` ${payload.length} `),
        payload,
    ]);
}

export function keyId(key: KeyObject): string {
    const publicKey = key.type === 'private' ? createPublicKey(key) : key;
    return `SHA256:${createHash('sha256')
        .update(publicKey.export({ type: 'spki', format: 'der' }))
        .digest('base64')}`;
}

export function generateSigningKey(
    directory: string,
    name = 'warden-attest'
): { privateKey: string; publicKey: string } {
    fs.mkdirSync(directory, { recursive: true });
    const privateKey = path.join(directory, `${name}.key`);
    const publicKey = path.join(directory, `${name}.pub`);
    if (fs.existsSync(privateKey))
        throw new Error(`${privateKey} already exists; refusing to overwrite it.`);
    const pair = generateKeyPairSync('ed25519');
    fs.writeFileSync(privateKey, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), {
        mode: 0o600,
        flag: 'wx',
    });
    fs.writeFileSync(publicKey, pair.publicKey.export({ type: 'spki', format: 'pem' }));
    return { privateKey, publicKey };
}

/** Build an in-toto statement whose subjects are the reviewed commit and lockfiles. */
export function statementFor(evidence: any): Statement {
    const kind = evidence?.kind === 'dependency-review' ? 'dependency-review' : 'verification';
    if (evidence?.schemaVersion !== 1 || !evidence.revisions?.head?.sha)
        throw new Error('Input is not a complete Warden verification or review evidence file.');
    const subject: Subject[] = [];
    for (const [label, revision] of Object.entries<any>(evidence.revisions)) {
        if (!/^[a-f0-9]{40,64}$/.test(revision?.sha ?? ''))
            throw new Error(`Invalid ${label} commit.`);
        subject.push({ name: `git-commit:${label}`, digest: { gitCommit: revision.sha } });
        if (revision.lockfileSha256)
            subject.push({
                name: `package-lock.json:${label}`,
                digest: { sha256: revision.lockfileSha256 },
            });
    }
    return {
        _type: STATEMENT_TYPE,
        subject,
        predicateType: PREDICATE_TYPES[kind],
        predicate: evidence,
    };
}

export function signStatement(statement: Statement, privateKeyPem: string): Envelope {
    const key = createPrivateKey(privateKeyPem);
    if (key.asymmetricKeyType !== 'ed25519')
        throw new Error('Signing key must be an Ed25519 private key.');
    const payload = Buffer.from(JSON.stringify(statement), 'utf8');
    return {
        payloadType: PAYLOAD_TYPE,
        payload: payload.toString('base64'),
        signatures: [
            {
                keyid: keyId(key),
                sig: sign(null, pae(PAYLOAD_TYPE, payload), key).toString('base64'),
            },
        ],
    };
}

export interface EnvelopeCheck {
    valid: boolean;
    keyid: string;
    statement?: Statement;
    reason?: string;
}

export function verifyEnvelope(envelope: Envelope, publicKeyPem: string): EnvelopeCheck {
    const key = createPublicKey(publicKeyPem);
    const id = keyId(key);
    if (envelope?.payloadType !== PAYLOAD_TYPE || typeof envelope.payload !== 'string')
        return { valid: false, keyid: id, reason: 'Unsupported envelope payload type.' };
    const payload = Buffer.from(envelope.payload, 'base64');
    const signed = (envelope.signatures ?? []).some(
        (s) =>
            typeof s?.sig === 'string' &&
            verify(null, pae(envelope.payloadType, payload), key, Buffer.from(s.sig, 'base64'))
    );
    if (!signed)
        return { valid: false, keyid: id, reason: 'No signature matches this public key.' };
    const statement = JSON.parse(payload.toString('utf8')) as Statement;
    if (statement._type !== STATEMENT_TYPE)
        return { valid: false, keyid: id, reason: 'Not an in-toto v1 statement.' };
    return { valid: true, keyid: id, statement };
}

/** Sign an evidence file and write `<name>.intoto.json` next to it (or to `output`). */
export function attestFile(evidencePath: string, privateKeyPath: string, output?: string): string {
    const evidence = JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
    const envelope = signStatement(statementFor(evidence), fs.readFileSync(privateKeyPath, 'utf8'));
    const target = output ?? evidencePath.replace(/\.json$/, '') + '.intoto.json';
    writeJsonAtomic(target, envelope);
    return target;
}
