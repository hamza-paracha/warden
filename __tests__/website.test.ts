import * as fs from 'fs';
import * as path from 'path';
import * as vm from 'vm';

const script = fs.readFileSync(path.join(__dirname, '../website/script.js'), 'utf8');

function page(clipboard?: { writeText: jest.Mock }) {
    let click: () => Promise<void> = async () => {};
    const classes = new Set<string>();
    const attributes: Record<string, string> = {};
    const button = {
        disabled: false,
        classList: {
            add: (name: string) => classes.add(name),
            remove: (name: string) => classes.delete(name),
        },
        setAttribute: (name: string, value: string) => {
            attributes[name] = value;
        },
        addEventListener: (_name: string, handler: typeof click) => {
            click = handler;
        },
    };
    const command = { textContent: ' npm install -g @devdonzo/warden ' };
    const status = { textContent: '' };
    const selection = { removeAllRanges: jest.fn(), addRange: jest.fn() };
    const range = { selectNodeContents: jest.fn() };
    const nodes: Record<string, unknown> = {
        'copy-btn': button,
        'install-command': command,
        'copy-status': status,
    };
    vm.runInNewContext(script, {
        document: {
            addEventListener: (_name: string, handler: () => void) => handler(),
            getElementById: (id: string) => nodes[id],
            createRange: () => range,
        },
        navigator: { clipboard },
        window: { getSelection: () => selection },
        setTimeout,
        clearTimeout,
    });
    return { click: () => click(), button, command, status, classes, attributes, range };
}

describe('website clipboard', () => {
    beforeEach(() => jest.useFakeTimers());
    afterEach(() => jest.useRealTimers());

    it('copies the displayed command and announces completion', async () => {
        const writeText = jest.fn().mockResolvedValue(undefined);
        const view = page({ writeText });
        await view.click();
        expect(writeText).toHaveBeenCalledWith('npm install -g @devdonzo/warden');
        expect(view.status.textContent).toBe('Install command copied.');
        expect(view.attributes['aria-label']).toBe('Copied install command');
        expect(view.button.disabled).toBe(false);
        jest.advanceTimersByTime(4000);
        expect(view.classes.size).toBe(0);
        expect(view.attributes['aria-label']).toBe('Copy install command');
    });

    it.each([undefined, { writeText: jest.fn().mockRejectedValue(new Error('denied')) }])(
        'provides a manual fallback when clipboard access fails',
        async (clipboard) => {
            const view = page(clipboard);
            await view.click();
            expect(view.status.textContent).toContain('Copy unavailable');
            expect(view.range.selectNodeContents).toHaveBeenCalledWith(view.command);
            expect(view.button.disabled).toBe(false);
        }
    );

    it('keeps the latest success state when copied repeatedly', async () => {
        const view = page({ writeText: jest.fn().mockResolvedValue(undefined) });
        await view.click();
        jest.advanceTimersByTime(3000);
        await view.click();
        jest.advanceTimersByTime(1000);
        expect(view.status.textContent).toBe('Install command copied.');
        jest.advanceTimersByTime(3000);
        expect(view.status.textContent).toBe('');
        expect(view.classes.size).toBe(0);
    });
});
