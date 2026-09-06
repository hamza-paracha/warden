/**
 * npm-audit Scanner Adapter
 *
 * Wraps the existing NpmAuditScanner class so it conforms to the IScanner interface.
 */

import { NpmAuditScanner } from '../agents/watchman/npm-audit';
import { IScanner, ScannerResult } from './index';

export class NpmAuditScannerAdapter implements IScanner {
    readonly name = 'npm-audit';

    private inner: NpmAuditScanner;

    constructor() {
        this.inner = new NpmAuditScanner();
    }

    async scan(): Promise<ScannerResult> {
        const result = await this.inner.scan();
        return result;
    }
}
