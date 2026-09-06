/**
 * Snyk Scanner Adapter
 *
 * Wraps the existing SnykScanner class so it conforms to the IScanner interface.
 */

import { SnykScanner, ScannerOptions } from '../agents/watchman/snyk';
import { IScanner, ScannerResult } from './index';

export class SnykScannerAdapter implements IScanner {
    readonly name = 'snyk';

    private inner: SnykScanner;

    constructor(options: ScannerOptions = {}) {
        this.inner = new SnykScanner(options);
    }

    async scan(): Promise<ScannerResult> {
        // SnykScanner.test() returns a compatible ScanResult shape
        const result = await this.inner.test();
        // Cast metadata field name: SnykScanner uses 'metadata', ScannerResult uses 'metadata'
        return result;
    }

    /** Expose the underlying scanner for utilities like filterHighPriority / printSummary */
    getInner(): SnykScanner {
        return this.inner;
    }
}
