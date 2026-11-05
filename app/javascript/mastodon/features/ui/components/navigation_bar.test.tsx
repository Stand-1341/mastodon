import { vi } from 'vitest';

import { render, screen } from '@/testing/rendering';
import * as initialStateModule from 'mastodon/initial_state';
import { useAppSelector } from 'mastodon/store';

import { NavigationBar } from './navigation_bar';

vi.mock('mastodon/store', () => ({
  useAppSelector: vi.fn(),
  useAppDispatch: () => vi.fn(),
}));

const PQC_TAB_LABEL = 'Encrypted messaging';

describe('<NavigationBar /> encrypted messaging entry', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    // The bar reads `state.navigation.open` and the unread notifications
    // count. Neither has a bearing on the PQC entry, so a canned value is
    // enough and avoids standing up a whole store.
    vi.mocked(useAppSelector).mockReturnValue(false);
  });

  it('renders the entry with the expected label and destination', () => {
    render(<NavigationBar />);

    const link = screen.getByRole('link', { name: PQC_TAB_LABEL });

    expect(link.getAttribute('href')).toBe('/pqc');
  });

  it('renders the entry with no feature flag or initial state present', () => {
    // The old gate read a `pqcE2eeExperimental` flag out of the initial
    // state. jsdom has no `#initial-state` element, so there is no initial
    // state here at all, and the constant must no longer be exported.
    expect(initialStateModule.initialState).toBeUndefined();
    expect('pqcE2eeExperimental' in initialStateModule).toBe(false);

    render(<NavigationBar />);

    expect(screen.getByRole('link', { name: PQC_TAB_LABEL })).toBeDefined();

    // It is an ordinary tab, rendered next to the other signed-in entries.
    expect(screen.getByRole('link', { name: 'Home' })).toBeDefined();
    expect(screen.getByRole('link', { name: 'Notifications' })).toBeDefined();
  });
});
