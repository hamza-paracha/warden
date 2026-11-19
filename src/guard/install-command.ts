import * as fs from 'fs';
import * as path from 'path';

export interface InstallTarget {
    manager: 'npm' | 'pnpm' | 'yarn' | 'bun';
    /** The spec exactly as typed. */
    spec: string;
    name?: string;
    range?: string;
    /** Executed immediately (npx/dlx) rather than only installed. */
    executes: boolean;
    /** Git, URL, or file specs bypass registry metadata and cannot be assessed. */
    source?: string;
}

const OPERATORS = new Set(['&&', '||', ';', '|', '&', '(', ')', '\n']);

/** Split a shell command into simple-command word lists without evaluating anything. */
export function tokenize(command: string): string[][] {
    const segments: string[][] = [[]];
    let word = '';
    let quoted = false;
    const push = () => {
        if (word || quoted) segments[segments.length - 1].push(word);
        word = '';
        quoted = false;
    };
    for (let i = 0; i < command.length; i++) {
        const char = command[i];
        if (char === "'" || char === '"') {
            const end = command.indexOf(char, i + 1);
            const stop = end < 0 ? command.length : end;
            word += command.slice(i + 1, stop).replace(char === '"' ? /\\(["\\$`])/g : /$^/, '$1');
            quoted = true;
            i = stop;
        } else if (char === '\\' && i + 1 < command.length) {
            if (command[i + 1] !== '\n') word += command[i + 1];
            i++;
        } else if (char === '#' && !word && !quoted) {
            const end = command.indexOf('\n', i);
            i = end < 0 ? command.length : end - 1;
        } else if (/\s/.test(char) && char !== '\n') push();
        else {
            const pair = command.slice(i, i + 2);
            const operator = OPERATORS.has(pair) ? pair : OPERATORS.has(char) ? char : undefined;
            if (!operator) {
                word += char;
                continue;
            }
            push();
            segments.push([]);
            i += operator.length - 1;
        }
    }
    push();
    return segments.filter((segment) => segment.length);
}

const WRAPPERS = new Set(['sudo', 'env', 'command', 'exec', 'time', 'nice', 'nohup', 'xargs']);
const VALUE_FLAGS = new Set([
    '--registry',
    '--prefix',
    '-C',
    '--workspace',
    '-w',
    '--tag',
    '--cache',
    '--userconfig',
    '--omit',
    '--include',
    '--install-strategy',
    '--save-prefix',
    '--filter',
    '-F',
    '--cwd',
    '--dir',
    '--network-concurrency',
    '--modules-folder',
    '--global-folder',
    '--loglevel',
    '--call',
    '-c',
]);
const NPM_INSTALL = new Set([
    'install',
    'i',
    'in',
    'ins',
    'inst',
    'insta',
    'instal',
    'isnt',
    'isnta',
    'isntal',
    'isntall',
    'add',
    'update',
    'up',
    'upgrade',
]);

function classify(
    manager: InstallTarget['manager'],
    spec: string,
    executes: boolean
): InstallTarget {
    if (
        /^(?:\.{0,2}\/|~|file:|link:|portal:|workspace:|git\+|git:|https?:|github:|gitlab:|bitbucket:|gist:)/.test(
            spec
        ) ||
        /\.t(?:ar\.)?gz$/.test(spec) ||
        (!spec.startsWith('@') && spec.includes('/'))
    ) {
        return { manager, spec, executes, source: spec };
    }
    let name = spec;
    let range: string | undefined;
    const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
    if (at > 0) {
        name = spec.slice(0, at);
        range = spec.slice(at + 1) || undefined;
    }
    // Aliases install a different package: alias@npm:real@range
    const alias = range?.match(/^npm:((?:@[^/@]+\/)?[^@]+)(?:@(.+))?$/);
    if (alias) {
        name = alias[1];
        range = alias[2];
    }
    if (range && /^(?:git|https?|file|github):/.test(range))
        return { manager, spec, executes, source: spec };
    return { manager, spec, name, range, executes };
}

function positionals(words: string[]): string[] {
    const result: string[] = [];
    for (let i = 0; i < words.length; i++) {
        const word = words[i];
        if (word === '--') {
            result.push(...words.slice(i + 1));
            break;
        }
        if (word.startsWith('-')) {
            if (!word.includes('=') && VALUE_FLAGS.has(word)) i++;
            continue;
        }
        result.push(word);
    }
    return result;
}

function packageFlags(words: string[]): string[] {
    const specs: string[] = [];
    for (let i = 0; i < words.length; i++) {
        if (words[i] === '-p' || words[i] === '--package') specs.push(words[++i]);
        else if (words[i].startsWith('--package=')) specs.push(words[i].slice(10));
    }
    return specs.filter(Boolean);
}

function localBinary(name: string, cwd: string): boolean {
    return fs.existsSync(path.join(cwd, 'node_modules', '.bin', name));
}

/** Runner arguments: the first positional is the package unless --package names it. */
function runner(manager: InstallTarget['manager'], args: string[], cwd: string): InstallTarget[] {
    const explicit = packageFlags(args);
    if (explicit.length) return explicit.map((spec) => classify(manager, spec, true));
    const spec = positionals(args)[0];
    if (!spec) return [];
    const target = classify(manager, spec, true);
    return target.name && !target.range && localBinary(target.name, cwd) ? [] : [target];
}

/** Find every package an agent's shell command would install or execute from a registry. */
export function findInstallTargets(command: string, cwd = process.cwd()): InstallTarget[] {
    const targets: InstallTarget[] = [];
    for (const segment of tokenize(command)) {
        let words = segment;
        while (
            words.length &&
            (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0]) || WRAPPERS.has(words[0]))
        )
            words = words.slice(1);
        if (!words.length) continue;
        const tool = path.basename(words[0]).replace(/\.(?:cmd|exe)$/, '');
        const args = words.slice(1);
        const [sub, ...rest] = positionals(args);
        const tail = args.slice(args.indexOf(sub) + 1);
        if (tool === 'npx' || tool === 'pnpx' || tool === 'bunx') {
            const manager = tool === 'npx' ? 'npm' : tool === 'pnpx' ? 'pnpm' : 'bun';
            targets.push(...runner(manager, args, cwd));
        } else if (tool === 'npm') {
            if (NPM_INSTALL.has(sub))
                targets.push(...positionals(tail).map((s) => classify('npm', s, false)));
            else if (sub === 'exec' || sub === 'x') targets.push(...runner('npm', tail, cwd));
            else if (sub === 'create' || sub === 'init') {
                if (rest[0] && !rest[0].startsWith('-')) {
                    const { name, range } = classify('npm', rest[0], true);
                    if (name) {
                        const full = name.startsWith('@')
                            ? name.includes('/')
                                ? name.replace('/', '/create-')
                                : `${name}/create`
                            : `create-${name}`;
                        targets.push(classify('npm', range ? `${full}@${range}` : full, true));
                    }
                }
            }
        } else if (tool === 'pnpm' || tool === 'yarn' || tool === 'bun') {
            const manager = tool;
            const words2 = sub === 'global' ? positionals(tail) : [sub, ...rest];
            const action = words2[0];
            const specs = words2.slice(1);
            if (action === 'dlx' || (tool === 'bun' && action === 'x')) {
                targets.push(...runner(manager, args.slice(args.indexOf(action) + 1), cwd));
            } else if (['add', 'a', 'install', 'i', 'update', 'up', 'upgrade'].includes(action)) {
                targets.push(...specs.map((s) => classify(manager, s, false)));
            }
        }
    }
    return targets;
}
