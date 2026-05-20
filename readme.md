# Google Authenticator export
I would like to export some codes from Google Authenticator, and get them into Proton.

## Usage

Run with a single migration URL:

```bash
php decode.php --url "otpauth-migration://offline?data=..." --out protonpass-export.csv --vault Personal
```

Run with a text file containing one migration URL per line:

```bash
php decode.php --input migration-urls.txt --out protonpass-export.csv --vault Personal
```

If no input is provided, the script uses the built-in sample URL in decode.php.

## Output

The script writes a Proton Pass CSV with header:

name,url,email,username,password,note,totp,vault

Behavior:

- Parses the Google Authenticator migration protobuf payload directly.
- Exports TOTP entries only.
- Skips HOTP entries and reports skip counts.
- Defaults algorithm to SHA1 and digits to 6 when unspecified.
- Uses smart mapping: account names that are emails go to email, otherwise username.

## Notes

- Keep the generated CSV private because it contains OTP secrets.
- Import a small subset into Proton first to smoke test before importing all entries.
