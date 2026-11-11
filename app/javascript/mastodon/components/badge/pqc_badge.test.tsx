import { IntlProvider } from 'react-intl';

import { MemoryRouter } from 'react-router-dom';

import { Map as ImmutableMap } from 'immutable';

import { render, screen, within } from '@testing-library/react';
import { vi } from 'vitest';

import { AccountBadges } from '@/mastodon/components/account_header/badges';
import { useAccount } from '@/mastodon/hooks/useAccount';
import type { Account, AccountShapeFull } from '@/mastodon/models/account';
import type { RootState } from '@/mastodon/store';
import { useAppSelector } from '@/mastodon/store';
import { accountFactoryImmutable } from '@/testing/factories';
import type { ApiAccountJSON } from 'mastodon/api_types/accounts';

import { StatusRedesignHeader } from '../status/header';

import { PqcBadge, VerifiedBadge } from '.';

const PQC_LABEL = 'Post-quantum signed';

vi.mock('@/mastodon/hooks/useAccount', () => ({
  useAccount: vi.fn(),
}));

vi.mock('@/mastodon/store', () => ({
  createAppSelector:
    (
      selectors: ((state: unknown) => unknown)[],
      combiner: (...values: unknown[]) => unknown,
    ) =>
    (state: unknown) =>
      combiner(...selectors.map((selector) => selector(state))),
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

  it('is distinguishable from <VerifiedBadge />', () => {
    const { container: pqcContainer } = renderBadge();
    const pqcBadge = pqcContainer.firstElementChild as HTMLElement;

    const { container: verifiedContainer } = render(
      <IntlProvider locale='en'>
        <VerifiedBadge link='https://example.com/@alice' />
      </IntlProvider>,
    );
    const verifiedBadge = verifiedContainer.firstElementChild as HTMLElement;

    // `PqcBadge` passes `variant='accent'` to <Badge /> while `VerifiedBadge`
    // passes `variant='success'`, so the two never share a class list.
    expect(pqcBadge.className).toContain('accent');
    expect(verifiedBadge.className).toContain('success');

    // Only the PQC badge turns the label into an accessible name, so the
    // verified badge can never be confused with it by assistive technology.
    expect(pqcBadge.getAttribute('role')).toBe('img');
    expect(pqcBadge.getAttribute('aria-label')).toBe(PQC_LABEL);
    expect(within(verifiedContainer).queryByRole('img')).toBeNull();
  });
});

describe('PQC badge in a post header', () => {
  it('shows the compact checkmark for signed post authors', () => {
    const account = accountFactoryImmutable({
      id: '1',
      acct: 'showcase_account',
      username: 'showcase_account',
      pqc_signed: true,
    });
    const accountShape = account.toJS() as AccountShapeFull;
    const state = { meta: ImmutableMap({ me: null }) };
    vi.mocked(useAccount).mockReturnValue(account);
    vi.mocked(useAppSelector).mockImplementation(
      (selector: (state: RootState) => unknown) =>
        selector(state as unknown as RootState),
    );

    render(
      <MemoryRouter>
        <IntlProvider locale='en'>
          <StatusRedesignHeader
            status={{
              id: 'status-1',
              account: accountShape,
              created_at: new Date().toISOString(),
              visibility: 'public',
              mentions: [],
            }}
          />
        </IntlProvider>
      </MemoryRouter>,
    );

    const badge = screen.getByRole('img', { name: PQC_LABEL });

    expect(badge.className).toContain('accent');
    expect(within(badge).queryByText(PQC_LABEL)).toBeNull();
  });
});

describe('<AccountBadges /> post-quantum badge', () => {
  const accountId = '1';

  const mountAccountBadges = (account: Account) => {
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

  const renderAccountBadges = (
    pqcSigned: boolean,
    accountOverrides: Partial<ApiAccountJSON> = {},
  ) =>
    mountAccountBadges(
      accountFactoryImmutable({
        id: accountId,
        pqc_signed: pqcSigned,
        ...accountOverrides,
      }),
    );

  it('shows the badge when the account has a post-quantum signing key', () => {
    renderAccountBadges(true);

    expect(screen.getByRole('img', { name: PQC_LABEL })).toBeDefined();
  });

  it('does not show the badge when the account is not post-quantum signed', () => {
    renderAccountBadges(false);

    expect(screen.queryByRole('img', { name: PQC_LABEL })).toBeNull();
  });

  it('keeps its own label when other badges are rendered alongside it', () => {
    renderAccountBadges(true, {
      bot: true,
      group: true,
      roles: [{ id: '2', name: 'Owner', color: '#000000' }],
    });

    expect(screen.getByText('Automated')).toBeDefined();
    expect(screen.getByText('Group')).toBeDefined();

    const badge = screen.getByRole('img', { name: PQC_LABEL });

    expect(badge.getAttribute('title')).toBe(PQC_LABEL);
    expect(badge.getAttribute('aria-label')).toBe(PQC_LABEL);
  });

  it('does not show the badge when the flag is missing from the payload', () => {
    // The account model defaults this field to false when a payload omits it.
    const account = accountFactoryImmutable({ id: accountId }).set(
      'pqc_signed',
      undefined as unknown as boolean,
    );

    expect(account.pqc_signed).toBe(false);

    mountAccountBadges(account);

    expect(screen.queryByRole('img', { name: PQC_LABEL })).toBeNull();
  });
});
