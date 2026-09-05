import { validator } from '../src/utils/validator';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

describe('Validator', () => {
    describe('validateEnvironment', () => {
        const originalEnv = process.env;

        beforeEach(() => {
            jest.resetModules();
            process.env = { ...originalEnv };
        });

        afterAll(() => {
            process.env = originalEnv;
        });

        it('should allow local scanning when GITHUB_TOKEN is missing', () => {
            delete process.env.GITHUB_TOKEN;
            const result = validator.validateEnvironment();

            expect(result.valid).toBe(true);
            expect(result.warnings).toContain(
                'GITHUB_TOKEN is not set; pull request creation will be skipped'
            );
        });

        it('should pass validation when GITHUB_TOKEN is present', () => {
            process.env.GITHUB_TOKEN = 'test-token';
            const result = validator.validateEnvironment();

            expect(result.valid).toBe(true);
            expect(result.errors.length).toBe(0);
        });

        it('should warn when SNYK_TOKEN is missing', () => {
            process.env.GITHUB_TOKEN = 'test-token';
            delete process.env.SNYK_TOKEN;

            const result = validator.validateEnvironment();

            expect(result.warnings.length).toBeGreaterThan(0);
            expect(result.warnings.some((w) => w.includes('SNYK_TOKEN'))).toBe(true);
        });
    });

    describe('validateDependencies', () => {
        it('should detect git installation', () => {
            const result = validator.validateDependencies();

            // Git should be installed on most systems
            const gitError = result.errors.find((e) => e.includes('Git'));
            expect(gitError).toBeUndefined();
        });

        it('should detect node installation', () => {
            const result = validator.validateDependencies();

            const nodeError = result.errors.find((e) => e.includes('Node.js'));
            expect(nodeError).toBeUndefined();
        });
    });

    describe('validateProjectManifest', () => {
        it('should validate package.json exists in project root', () => {
            const projectRoot = path.resolve(__dirname, '..');
            const result = validator.validateProjectManifest(projectRoot);

            expect(result.valid).toBe(true);
            expect(result.errors.length).toBe(0);
        });

        it('should validate a Python requirements project', () => {
            const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'warden-python-'));
            fs.writeFileSync(path.join(tempDir, 'requirements.txt'), 'jinja2==2.11.2\n', 'utf-8');
            const result = validator.validateProjectManifest(tempDir);

            expect(result.valid).toBe(true);
            expect(result.errors.length).toBe(0);
            fs.rmSync(tempDir, { recursive: true, force: true });
        });

        it('should fail when no supported manifest exists', () => {
            const nonExistentPath = '/tmp/nonexistent-path-12345';
            const result = validator.validateProjectManifest(nonExistentPath);

            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('No supported manifest found'))).toBe(true);
        });
    });

    describe('sanitizeRepositoryUrl', () => {
        it('should handle HTTPS GitHub URLs', () => {
            const result = validator.sanitizeRepositoryUrl('https://github.com/DevDonzo/warden');
            expect(result).toBe('https://github.com/DevDonzo/warden');
        });

        it('should handle HTTPS GitHub URLs with .git suffix', () => {
            const result = validator.sanitizeRepositoryUrl(
                'https://github.com/DevDonzo/warden.git'
            );
            expect(result).toBe('https://github.com/DevDonzo/warden');
        });

        it('should handle SSH GitHub URLs', () => {
            const result = validator.sanitizeRepositoryUrl('git@github.com:DevDonzo/warden.git');
            expect(result).toBe('https://github.com/DevDonzo/warden');
        });

        it('should handle github.com/ prefix format', () => {
            const result = validator.sanitizeRepositoryUrl('github.com/DevDonzo/warden');
            expect(result).toBe('https://github.com/DevDonzo/warden');
        });

        it('should handle owner/repo shorthand', () => {
            const result = validator.sanitizeRepositoryUrl('DevDonzo/warden');
            expect(result).toBe('https://github.com/DevDonzo/warden');
        });

        it('should handle local paths', () => {
            const result = validator.sanitizeRepositoryUrl('/path/to/local/repo');
            expect(result).toBe('/path/to/local/repo');
        });

        it('should handle relative paths', () => {
            const result = validator.sanitizeRepositoryUrl('./local-repo');
            expect(result).toBe('./local-repo');
        });

        it('should return null for empty input', () => {
            const result = validator.sanitizeRepositoryUrl('');
            expect(result).toBeNull();
        });

        it('should return null for invalid URL', () => {
            const result = validator.sanitizeRepositoryUrl('not-a-valid-url!!!');
            expect(result).toBeNull();
        });

        it('should trim whitespace', () => {
            const result = validator.sanitizeRepositoryUrl(
                '  https://github.com/DevDonzo/warden  '
            );
            expect(result).toBe('https://github.com/DevDonzo/warden');
        });
    });

    describe('validateRepositoryUrl', () => {
        it('should validate correct HTTPS URLs', () => {
            const result = validator.validateRepositoryUrl('https://github.com/DevDonzo/warden');
            expect(result.valid).toBe(true);
            expect(result.errors.length).toBe(0);
        });

        it('should validate owner/repo shorthand', () => {
            const result = validator.validateRepositoryUrl('DevDonzo/warden');
            expect(result.valid).toBe(true);
            expect(result.errors.length).toBe(0);
        });

        it('should reject empty string', () => {
            const result = validator.validateRepositoryUrl('');
            expect(result.valid).toBe(false);
            expect(result.errors).toContain('Repository URL cannot be empty');
        });

        it('should reject invalid formats', () => {
            const result = validator.validateRepositoryUrl('invalid!!!url');
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('Invalid repository format'))).toBe(true);
        });

        it('should reject URLs with spaces', () => {
            const result = validator.validateRepositoryUrl('https://github.com/Dev Donzo/warden');
            expect(result.valid).toBe(false);
        });

        it('should reject extremely long URLs', () => {
            const longUrl = 'https://github.com/' + 'a'.repeat(500) + '/repo';
            const result = validator.validateRepositoryUrl(longUrl);
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('too long'))).toBe(true);
        });
    });

    describe('validateBranchName', () => {
        it('should validate correct warden branch names', () => {
            const result = validator.validateBranchName('warden/fix-package-name');
            expect(result.valid).toBe(true);
        });

        it('should validate other valid branch patterns', () => {
            const result = validator.validateBranchName('feature/new-feature');
            expect(result.valid).toBe(true);
        });

        it('should reject empty string', () => {
            const result = validator.validateBranchName('');
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('cannot be empty'))).toBe(true);
        });

        it('should reject branch names with spaces', () => {
            const result = validator.validateBranchName('warden/fix my package');
            expect(result.valid).toBe(false);
            expect(
                result.errors.some((e) => e.includes('cannot contain control characters or spaces'))
            ).toBe(true);
        });

        it('should reject branch names starting with /', () => {
            const result = validator.validateBranchName('/invalid-branch');
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('cannot start or end with /'))).toBe(true);
        });

        it('should reject branch names ending with /', () => {
            const result = validator.validateBranchName('invalid-branch/');
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('cannot start or end with /'))).toBe(true);
        });

        it('should reject branch names with ..', () => {
            const result = validator.validateBranchName('feature/../invalid');
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('cannot contain ".."'))).toBe(true);
        });

        it('should reject branch names with special characters', () => {
            const invalidChars = ['~', '^', ':', '?', '*', '[', '\\'];
            invalidChars.forEach((char) => {
                const result = validator.validateBranchName(`invalid${char}branch`);
                expect(result.valid).toBe(false);
            });
        });

        it('should reject branch name ending with .lock', () => {
            const result = validator.validateBranchName('branch.lock');
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('Invalid branch name format'))).toBe(true);
        });

        it('should reject branch name that is just @', () => {
            const result = validator.validateBranchName('@');
            expect(result.valid).toBe(false);
        });

        it('should reject extremely long branch names', () => {
            const longName = 'warden/fix-' + 'a'.repeat(300);
            const result = validator.validateBranchName(longName);
            expect(result.valid).toBe(false);
            expect(result.errors.some((e) => e.includes('too long'))).toBe(true);
        });

        it('should warn for warden branches with incorrect format', () => {
            const result = validator.validateBranchName('warden/invalid_format');
            expect(result.warnings.length).toBeGreaterThan(0);
            expect(result.warnings.some((w) => w.includes('should follow format'))).toBe(true);
        });

        it('should accept valid warden branch types', () => {
            const validTypes = ['fix', 'feat', 'chore', 'docs', 'refactor', 'test'];
            validTypes.forEach((type) => {
                const result = validator.validateBranchName(`warden/${type}-description`);
                expect(result.valid).toBe(true);
            });
        });
    });

    describe('sanitizeBranchName', () => {
        it('should sanitize package names with special characters', () => {
            const result = validator.sanitizeBranchName('@babel/core');
            expect(result).toBe('warden/fix-at-babel-core');
        });

        it('should remove spaces and replace with hyphens', () => {
            const result = validator.sanitizeBranchName('my package name');
            expect(result).toBe('warden/fix-my-package-name');
        });

        it('should handle consecutive special characters', () => {
            const result = validator.sanitizeBranchName('package~~~name');
            expect(result).toBe('warden/fix-package-name');
        });

        it('should truncate very long names', () => {
            const longName = 'a'.repeat(300);
            const result = validator.sanitizeBranchName(longName);
            expect(result.length).toBeLessThan(220);
            expect(result.startsWith('warden/fix-')).toBe(true);
        });

        it('should handle names with .lock suffix', () => {
            const result = validator.sanitizeBranchName('package.lock');
            expect(result).toBe('warden/fix-package');
        });

        it('should lowercase the result', () => {
            const result = validator.sanitizeBranchName('MyPackageName');
            expect(result).toBe('warden/fix-mypackagename');
        });

        it('should handle empty input', () => {
            const result = validator.sanitizeBranchName('');
            expect(result).toBe('warden/fix-unknown');
        });

        it('should preserve warden/ prefix if already present', () => {
            const result = validator.sanitizeBranchName('warden/fix-something', 'warden/feat');
            expect(result.startsWith('warden/')).toBe(true);
        });

        it('should use custom prefix when provided', () => {
            const result = validator.sanitizeBranchName('myfeature', 'warden/feat');
            expect(result).toBe('warden/feat-myfeature');
        });

        it('should remove trailing dots and hyphens', () => {
            const result = validator.sanitizeBranchName('package-name...');
            expect(result).not.toMatch(/[.-]$/);
        });
    });
});
