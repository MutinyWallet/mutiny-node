# Testing

Things to test before cutting a release:

- `just test`/CI passes
- Receive on lightning
  - One that creates a channel
  - One that uses an existing channel
- Send on lightning
  - Small amount (1 sat)
  - Medium amount (1,000 sat)
  - Large amount (100,000 sat)
- Receive on chain
- Send on chain
- Swap to lightning
- Nostr Wallet Connect
  - Auto approval
  - Manual approval
  - Editing a budget
  - Gifting
- Syncing Nostr Contacts
- Adding a contact
- Restore from seed
- Adding an encryption password
  - Make sure we can decrypt wallet
- Changing an encryption password
- Restoring with an encryption password
- Export logs
  - Try with and without encryption password
- Mutual Close Channel
  - Known Issue: balance will be double counted until 6 confirmations
- Force Close Channel
