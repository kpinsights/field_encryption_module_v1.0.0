# REDCap Field Encryption Module

An External Module that encrypts field values marked with `@ENCRYPT`. Designed for studies that need to collect participant emails for automated survey invitations while keeping those emails hidden from anyone viewing the data.

## The Problem

REDCap's Automated Survey Invitations require an email field to send follow-up surveys. But that email is visible to anyone with data access. For studies promising participant anonymity, this is a problem.

## What This Module Does

When a participant submits their survey, the module encrypts it and saves it back to the database in a format like `ENC_abc123xyz...@xx.xx`. This fake email format passes REDCap's email validation but is unreadable.

When it's time to send a survey invitation, a cron job decrypts the email address and sends the invitation. The participant receives their survey. Staff never see the real email.

In data entry forms and reports, the field displays `encrypted@xx.xx`.

## Requirements

- REDCap 15.0.0+
- PHP 7.4.0+
- External Module Framework v16
- Working mail configuration (Postfix, sendmail, or SMTP)

## Installation

1. Place the module folder in your REDCap `modules` directory
2. Enable the module in Control Center > External Modules
3. Configure the Master Encryption Key (generate one with `openssl rand -hex 32`)
4. Enable for your project

## Usage

Add `@ENCRYPT` to any field's action tags. That field will be encrypted on save.

For email encryption with ASI:
1. Add `@ENCRYPT` to your email field
2. Set up Automated Survey Invitations as normal
3. Select the encrypted email field as the recipient

The module's cron runs every 30 seconds and handles delivery.

## Encryption

The module uses SaferCrypto, which implements AES-256-CTR with HMAC-SHA256 authentication (encrypt-then-MAC).

Encrypted values are base64 encoded, converted to URL-safe characters, and formatted as `ENC_[data]@xx.xx`. This format passes REDCap's email validation while being obviously not a real address.

The encryption classes (UnsafeCrypto and SaferCrypto) are based on code by [Scott Arciszewski](https://stackoverflow.com/questions/9262109/simplest-two-way-encryption-using-php), licensed under CC BY-SA 4.0.

## What the Module Does at Each Step

**On record save / survey submit:**
- Hooks `redcap_save_record` and `redcap_survey_complete` fire
- For survey saves, encryption is deferred until the form status is Complete — this prevents validation errors on paginated surveys
- Module reads the data dictionary for fields with `@ENCRYPT`
- Fetches the saved record data via `REDCap::getData()`
- Encrypts any unencrypted values and saves them back via `REDCap::saveData()` with `$bypassValidationCheck` enabled
- If the encrypted field is the project's designated participant email field, updates `redcap_surveys_participants` table so ASI can find it

**On data entry form load:**
- Shows a privacy notice banner at the top of forms with encrypted fields
- JavaScript replaces any `ENC_...@xx.xx` values with `encrypted@xx.xx`
- The field becomes read-only with an overlay blocking interaction
- Validation handlers are removed to prevent popups

**On survey page load (returning participants only):**
- Same masking as data entry forms, but only if the participant already has a saved response

**On report generation:**
- The `redcap_report_data` hook replaces encrypted values with `[ENCRYPTED]`

**On email send:**
- The `redcap_email` hook checks if the recipient matches `ENC_...@xx.xx`
- If so, decrypts and sends to the real address, then returns `false` to prevent REDCap from also trying to send

**Cron job (every 30 seconds):**
- Syncs encrypted emails across participant records for longitudinal projects
- Queries `redcap_surveys_scheduler_queue` for pending invitations with encrypted emails
- Also picks up invitations marked `DID NOT SEND` / `EMAIL ATTEMPT FAILED` (in case REDCap's cron tried first)
- Decrypts the email, builds the survey link from the participant hash, sends via `REDCap::email()`
- Updates queue status to `SENT`

## Files

| File | Description |
|------|-------------|
| `FieldEncryptionModule.php` | Main module class |
| `SaferCrypto.php` | Authenticated encryption (encrypt-then-MAC) |
| `UnsafeCrypto.php` | AES-256-CTR encryption |
| `config.json` | Module settings, hooks, cron definition |

## Security Notes

- Decrypted values are never written to logs
- SQL queries use parameterized statements via `$module->query()`
- JavaScript is wrapped in an IIFE to avoid global scope pollution
- Field names are JSON-encoded with `JSON_HEX_*` flags to prevent XSS
- Survey links in emails are escaped with `REDCap::escapeHtml()`

## Limitations

- Email addresses cannot be viewed or corrected after encryption
- Only works with email-based ASI, not SMS
- Requires REDCap's cron to be running (the module's cron is triggered by it)
- If you lose the encryption key, encrypted data is unrecoverable

## Troubleshooting

**Emails not sending:** Check that REDCap's cron is running. Look at the EM logs for errors.

**Field not encrypting:** Verify `@ENCRYPT` is in the field's action tags. Check EM logs for "Could not fetch record data" which indicates an event/instrument mismatch.

**Still seeing encrypted string instead of `encrypted@xx.xx`:** Browser might be blocking JavaScript. Check console for errors.

## Authors

Kshitiz Pokhrel - Toronto Metropolitan University (kpokhrel@torontomu.ca)

Ryan McRonald - University of Victoria (rmcronald@uvic.ca)

## License

MIT License. See LICENSE file.
