# Server-backed accounts and points

The Express app uses PostgreSQL for accounts, sessions, package participation,
wallet ledger entries, referral rewards, and daily reward claims. On startup it
creates the required tables and adds account columns to the existing `users`
table. Install dependencies with `npm install`, set `DATABASE_URL` and
`NODE_ENV=production` on the server, then start with `npm start`. Host the site
over HTTPS so session cookies are marked `Secure`.
`DATABASE_SSL=false` is only for a local PostgreSQL instance that does not use
TLS.

Passwords are stored as scrypt hashes. Login sessions are random, HttpOnly,
SameSite=Strict cookies; only their SHA-256 hashes are stored in the database.
The existing browser-only accounts and balances are intentionally not imported:
they can be edited in the browser. Users must register a server account. New
accounts receive the 20,000-point signup bonus from the server.

## Server-side point rules

- Package prices and names are validated by the server, and purchases debit the
  authenticated account inside a database transaction.
- A referral reward is credited to the recorded referrer after a referred user
  successfully joins a package.
- Daily task points start the calendar day after package purchase, are 10% of
  each eligible package price, and can be claimed once per Vietnam calendar day
  for up to 30 eligible days. The account balance, ledger entry, and unique
  daily claim are committed atomically.
- All balance and history reads use the authenticated server account. The
  browser cannot choose the account ID or submit a reward amount.

## Payment processing

The current deposit orders are held in server memory and the SePay webhook does
not verify signed requests or process transaction IDs idempotently. Do not
accept real transfers until persistent orders and signed, replay-protected,
idempotent payment processing are implemented.

Withdrawal requests are stored in PostgreSQL and require a successful deposit
and package participation. New bank details are encrypted before they are
stored. Configure the encryption key below before users save bank details or
submit a withdrawal request. Only treat a withdrawal as paid after the bank
transfer has been completed and verified by an administrator.

Email verification, password reset, and administrative account recovery are
not implemented. Add those before using the account system for a public
financial service. Keep database credentials and all payment secrets in the
hosting provider's environment settings; never put them in the HTML or commit
them to source control.

## Saved bank details

The withdrawal form saves the bank name, account number, and account holder
name to the authenticated user's account when the user explicitly saves them
or sends the first withdrawal request. They are fetched again when the user
opens the withdrawal form.

Set `BANK_DETAILS_ENCRYPTION_KEY` in the hosting provider's environment settings
to a randomly generated 32-byte (64-character hex) key. Generate a key locally
with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
and paste it directly into the provider settings. Do not commit the key or send
it in chat. The server encrypts saved bank details and new withdrawal records
with AES-256-GCM. Keep a secure backup of this key; stored details cannot be
decrypted if it is lost or changed.

The admin withdrawal endpoints require `ADMIN_API_TOKEN`. Configure a long,
random token in server settings and include it in the `Authorization` request
header when calling those endpoints. Without that setting, admin operations
are disabled.
