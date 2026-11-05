import { IntlProvider } from 'react-intl';

import { Map as ImmutableMap } from 'immutable';

import { render, screen } from '@testing-library/react';
import { vi } from 'vitest';

import { AccountBadges } from '@/mastodon/components/account_header/badges';
import { useAccount } from '@/mastodon/hooks/useAccount';
import type { RootState } from '@/mastodon/store';
import { useAppSelector } from '@/mastodon/store';
import { accountFactoryImmutable } from '@/testing/factories';

import { PqcBadge } from '.';

const PQC_LABEL = 'Post-quantum signed';

vi.mock('@/mastodon/hooks/useAccount', () => ({
  useAccount: vi.fn(),
}));

vi.mock('@/mastodon/store', () => ({
  useAppSelector: vi.fn(),
  useAppDispatch: () => vi.fn(),
}));

describe('<PqcBadge />', () => {
  const renderBadge = () =>
    render(
      <IntlProvider locale='en'>
        <PqcBadge />
      </IntlProvider>,
    );

  it('renders the post-quantum signed label', () => {
    renderBadge();

    expect(screen.getByText(PQC_LABEL)).toBeDefined();
  });

  it('exposes the label as the accessible name of an img role', () => {
    renderBadge();

    const badge = screen.getByRole('img', { name: PQC_LABEL });

    expect(badge.getAttribute('title')).toBe(PQC_LABEL);
  });
});

describe('<AccountBadges /> post-quantum badge', () => {
  const accountId = '1';

  const renderAccountBadges = (pqcSigned: boolean) => {
    const account = accountFactoryImmutable({
      id: accountId,
      pqc_signed: pqcSigned,
    });

    const state = {
      meta: ImmutableMap({ domain: 'example.com' }),
      relationships: ImmutableMap({
        [accountId]: ImmutableMap({
          blocking: false,
          domain_blocking: false,
          muting: false,
        }),
      }),
    };

    vi.mocked(useAccount).mockReturnValue(account);
    vi.mocked(useAppSelector).mockImplementation(
      (selector: (state: RootState) => unknown) =>
        selector(state as unknown as RootState),
    );

    return render(
      <IntlProvider locale='en'>
        <AccountBadges accountId={accountId} />
      </IntlProvider>,
    );
  };

  it('shows the badge when the account has a post-quantum signing key', () => {
    renderAccountBadges(true);

    expect(screen.getByRole('img', { name: PQC_LABEL })).toBeDefined();
  });

  it('does not show the badge when the account is not post-quantum signed', () => {
    renderAccountBadges(false);

    expect(screen.queryByRole('img', { name: PQC_LABEL })).toBeNull();
  });
});
