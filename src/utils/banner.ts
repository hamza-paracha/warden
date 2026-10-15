import chalk from 'chalk';

const BANNER_LINES = [
    '           /\\',
    '        .-/  \\-.',
    '      ./  ____  \\.',
    '     /   / /\\ \\   \\',
    '    |   / /  \\ \\   |',
    '    |   \\ \\__/ /   |',
    '     \\   \\____/   /',
    '      \\    __    /',
    '       `-.____.-`',
];

export function renderWardenBanner(version?: string): string {
    const frame = chalk.hex('#5eead4');
    const dim = chalk.hex('#64748b');
    const title = chalk.hex('#ecfeff').bold;
    const accent = chalk.hex('#fbbf24');
    const versionLabel = version ? dim(` v${version}`) : '';

    return [
        '',
        ...BANNER_LINES.map((line) => frame(line)),
        `${title('        W A R D E N')}${versionLabel}`,
        dim('   dependency security and verification'),
        accent('   scan  |  verify  |  baseline  |  report'),
        '',
    ].join('\n');
}

export function printWardenBanner(version?: string): void {
    console.log(renderWardenBanner(version));
}
