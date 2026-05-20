<?php

declare(strict_types=1);

main($argv);

function main(array $argv): void
{
	$options = parseArguments($argv);

	if (!empty($options['help'])) {
		printUsage();
		return;
	}

	$urls = collectUrls($options);
	if ($urls === []) {
		fwrite(STDERR, "No migration URLs found.\n");
		exit(1);
	}

	$rows = [];
	$stats = [
		'payloads' => 0,
		'parsed' => 0,
		'exported' => 0,
		'skipped_hotp' => 0,
		'failed' => 0,
	];

	foreach ($urls as $urlIndex => $url) {
		try {
			$payloadBinary = decodeMigrationPayloadFromUrl($url);
			$payload = parseMigrationPayload($payloadBinary);
			$stats['payloads']++;

			foreach ($payload['otp_parameters'] as $entryIndex => $otp) {
				$stats['parsed']++;
				$type = normalizeOtpType((int)($otp['type'] ?? 0));
				if ($type !== 'TOTP') {
					$stats['skipped_hotp']++;
					fwrite(STDERR, "Skipping HOTP entry at payload {$urlIndex}, entry {$entryIndex}.\n");
					continue;
				}

				if (!isset($otp['secret']) || $otp['secret'] === '') {
					$stats['failed']++;
					fwrite(STDERR, "Skipping entry with empty secret at payload {$urlIndex}, entry {$entryIndex}.\n");
					continue;
				}

				$context = [
					'payload_index' => $urlIndex,
					'entry_index' => $entryIndex,
					'batch_id' => (string)($payload['batch_id'] ?? ''),
					'batch_index' => (string)($payload['batch_index'] ?? ''),
				];

				$row = mapOtpToProtonRow($otp, $options['vault'], $context);
				$errors = validateProtonRow($row);
				if ($errors !== []) {
					$stats['failed']++;
					fwrite(STDERR, "Row validation failed at payload {$urlIndex}, entry {$entryIndex}: " . implode('; ', $errors) . "\n");
					continue;
				}

				$rows[] = $row;
				$stats['exported']++;
			}
		} catch (RuntimeException $exception) {
			$stats['failed']++;
			fwrite(STDERR, "Failed to process payload {$urlIndex}: {$exception->getMessage()}\n");
		}
	}

	writeProtonCsv($options['out'], $rows);

	echo "Done.\n";
	echo "Payloads parsed: {$stats['payloads']}\n";
	echo "OTP entries parsed: {$stats['parsed']}\n";
	echo "Rows exported: {$stats['exported']}\n";
	echo "Rows skipped (HOTP): {$stats['skipped_hotp']}\n";
	echo "Rows failed: {$stats['failed']}\n";
	echo "Output CSV: {$options['out']}\n";
}

function parseArguments(array $argv): array
{
	$options = [
		'url' => null,
		'input' => null,
		'out' => 'protonpass-export.csv',
		'vault' => 'Personal',
		'help' => false,
	];

	for ($i = 1, $count = count($argv); $i < $count; $i++) {
		$arg = $argv[$i];
		switch ($arg) {
			case '--url':
				$options['url'] = $argv[$i + 1] ?? null;
				$i++;
				break;
			case '--input':
				$options['input'] = $argv[$i + 1] ?? null;
				$i++;
				break;
			case '--out':
				$options['out'] = $argv[$i + 1] ?? $options['out'];
				$i++;
				break;
			case '--vault':
				$options['vault'] = $argv[$i + 1] ?? $options['vault'];
				$i++;
				break;
			case '--help':
			case '-h':
				$options['help'] = true;
				break;
			default:
				throw new RuntimeException("Unknown argument: {$arg}");
		}
	}

	return $options;
}

function printUsage(): void
{
	echo "Usage:\n";
	echo "  php decode.php --url \"otpauth-migration://...\" [--out protonpass-export.csv] [--vault Personal]\n";
	echo "  php decode.php --input migration-urls.txt [--out protonpass-export.csv] [--vault Personal]\n";
	echo "\n";
	echo "If neither --url nor --input is provided, a built-in sample URL is used.\n";
}

function collectUrls(array $options): array
{
	if (is_string($options['url']) && trim($options['url']) !== '') {
		return [trim($options['url'])];
	}

	if (is_string($options['input']) && trim($options['input']) !== '') {
		$path = trim($options['input']);
		if (!is_file($path)) {
			throw new RuntimeException("Input file not found: {$path}");
		}

		$lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		if ($lines === false) {
			throw new RuntimeException("Unable to read input file: {$path}");
		}

		return array_values(array_filter(array_map('trim', $lines), static fn(string $line): bool => $line !== ''));
	}

	fwrite(STDERR, "No --url or --input provided.\n");
	return [];
}

function decodeMigrationPayloadFromUrl(string $url): string
{
	$query = parse_url($url, PHP_URL_QUERY);
	if (!is_string($query) || $query === '') {
		throw new RuntimeException('URL does not include query parameters.');
	}

	parse_str($query, $params);
	if (!isset($params['data']) || !is_string($params['data']) || $params['data'] === '') {
		throw new RuntimeException('URL is missing the data query parameter.');
	}

	$base64 = urldecode($params['data']);
	$decoded = base64_decode($base64, true);
	if ($decoded === false) {
		throw new RuntimeException('data parameter is not valid base64.');
	}

	return $decoded;
}

function parseMigrationPayload(string $binary): array
{
	$reader = new ProtoReader($binary);
	$payload = [
		'otp_parameters' => [],
		'version' => 0,
		'batch_size' => 0,
		'batch_index' => 0,
		'batch_id' => 0,
	];

	while (!$reader->isEof()) {
		$key = $reader->readVarint();
		$field = $key >> 3;
		$wire = $key & 0x07;

		if ($field === 1 && $wire === 2) {
			$entryBinary = $reader->readLengthDelimited();
			$payload['otp_parameters'][] = parseOtpParameters($entryBinary);
			continue;
		}

		if ($wire === 0) {
			$value = $reader->readVarint();
			if ($field === 2) {
				$payload['version'] = $value;
			} elseif ($field === 3) {
				$payload['batch_size'] = $value;
			} elseif ($field === 4) {
				$payload['batch_index'] = $value;
			} elseif ($field === 5) {
				$payload['batch_id'] = $value;
			}
			continue;
		}

		$reader->skipByWireType($wire);
	}

	return $payload;
}

function parseOtpParameters(string $binary): array
{
	$reader = new ProtoReader($binary);
	$otp = [
		'secret' => '',
		'name' => '',
		'issuer' => '',
		'algorithm' => 0,
		'digits' => 0,
		'type' => 0,
		'counter' => 0,
	];

	while (!$reader->isEof()) {
		$key = $reader->readVarint();
		$field = $key >> 3;
		$wire = $key & 0x07;

		if ($wire === 2) {
			$value = $reader->readLengthDelimited();
			if ($field === 1) {
				$otp['secret'] = $value;
			} elseif ($field === 2) {
				$otp['name'] = $value;
			} elseif ($field === 3) {
				$otp['issuer'] = $value;
			}
			continue;
		}

		if ($wire === 0) {
			$value = $reader->readVarint();
			if ($field === 4) {
				$otp['algorithm'] = $value;
			} elseif ($field === 5) {
				$otp['digits'] = $value;
			} elseif ($field === 6) {
				$otp['type'] = $value;
			} elseif ($field === 7) {
				$otp['counter'] = $value;
			}
			continue;
		}

		$reader->skipByWireType($wire);
	}

	return $otp;
}

function normalizeAlgorithm(int $algorithm): string
{
	return match ($algorithm) {
		2 => 'SHA256',
		3 => 'SHA512',
		4 => 'MD5',
		default => 'SHA1',
	};
}

function normalizeDigits(int $digits): int
{
	return $digits === 2 ? 8 : 6;
}

function normalizeOtpType(int $type): string
{
	return $type === 1 ? 'HOTP' : 'TOTP';
}

function base32Encode(string $binary): string
{
	if ($binary === '') {
		return '';
	}

	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$bitBuffer = 0;
	$bitCount = 0;
	$output = '';
	$length = strlen($binary);

	for ($i = 0; $i < $length; $i++) {
		$bitBuffer = ($bitBuffer << 8) | ord($binary[$i]);
		$bitCount += 8;

		while ($bitCount >= 5) {
			$index = ($bitBuffer >> ($bitCount - 5)) & 0x1F;
			$output .= $alphabet[$index];
			$bitCount -= 5;
		}
	}

	if ($bitCount > 0) {
		$index = ($bitBuffer << (5 - $bitCount)) & 0x1F;
		$output .= $alphabet[$index];
	}

	return $output;
}

function buildTitle(string $issuer, string $account, int $payloadIndex, int $entryIndex): string
{
	if ($issuer !== '' && $account !== '') {
		return "{$issuer}: {$account}";
	}
	if ($account !== '') {
		return $account;
	}
	if ($issuer !== '') {
		return $issuer;
	}
	return "Imported OTP {$payloadIndex}-{$entryIndex}";
}

function mapOtpToProtonRow(array $otp, string $vault, array $context): array
{
	$issuer = trim((string)($otp['issuer'] ?? ''));
	$account = trim((string)($otp['name'] ?? ''));
	$title = buildTitle($issuer, $account, (int)$context['payload_index'], (int)$context['entry_index']);

	$algorithm = normalizeAlgorithm((int)($otp['algorithm'] ?? 0));
	$digits = normalizeDigits((int)($otp['digits'] ?? 0));
	$secret = base32Encode((string)$otp['secret']);

	$label = rawurlencode($title);
	$query = [
		'secret' => $secret,
		'algorithm' => $algorithm,
		'digits' => (string)$digits,
		'period' => '30',
	];
	if ($issuer !== '') {
		$query['issuer'] = $issuer;
	}
	$totp = 'otpauth://totp/' . $label . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

	$email = '';
	$username = '';
	if ($account !== '' && filter_var($account, FILTER_VALIDATE_EMAIL)) {
		$email = $account;
	} else {
		$username = $account;
	}

	$noteParts = [
		'source=google-authenticator-migration',
		'type=TOTP',
	];
	if ($issuer !== '') {
		$noteParts[] = 'issuer=' . $issuer;
	}
	if ($account !== '') {
		$noteParts[] = 'account=' . $account;
	}
	if ((string)$context['batch_id'] !== '') {
		$noteParts[] = 'batch_id=' . $context['batch_id'];
	}
	if ((string)$context['batch_index'] !== '') {
		$noteParts[] = 'batch_index=' . $context['batch_index'];
	}

	return [
		'name' => $title,
		'url' => '',
		'email' => $email,
		'username' => $username,
		'password' => '',
		'note' => implode('; ', $noteParts),
		'totp' => $totp,
		'vault' => $vault,
	];
}

function validateProtonRow(array $row): array
{
	$errors = [];

	if (!isset($row['name']) || trim((string)$row['name']) === '') {
		$errors[] = 'name is empty';
	}

	if (!isset($row['totp']) || trim((string)$row['totp']) === '') {
		$errors[] = 'totp is empty';
		return $errors;
	}

	$uri = parse_url((string)$row['totp']);
	if ($uri === false) {
		$errors[] = 'totp is not a valid URI';
		return $errors;
	}

	if (($uri['scheme'] ?? '') !== 'otpauth') {
		$errors[] = 'totp scheme must be otpauth';
	}
	if (($uri['host'] ?? '') !== 'totp') {
		$errors[] = 'totp type must be totp';
	}

	parse_str((string)($uri['query'] ?? ''), $query);
	$secret = (string)($query['secret'] ?? '');
	$algorithm = (string)($query['algorithm'] ?? '');
	$digits = (string)($query['digits'] ?? '');
	$period = (string)($query['period'] ?? '');

	if ($secret === '' || preg_match('/^[A-Z2-7]+$/', $secret) !== 1) {
		$errors[] = 'secret is missing or not valid base32';
	}
	if (!in_array($algorithm, ['SHA1', 'SHA256', 'SHA512', 'MD5'], true)) {
		$errors[] = 'algorithm is invalid';
	}
	if (!in_array($digits, ['6', '8'], true)) {
		$errors[] = 'digits must be 6 or 8';
	}
	if (!ctype_digit($period) || (int)$period <= 0) {
		$errors[] = 'period must be a positive integer';
	}

	return $errors;
}

function writeProtonCsv(string $path, array $rows): void
{
	$handle = fopen($path, 'wb');
	if ($handle === false) {
		throw new RuntimeException("Unable to open output file: {$path}");
	}

	$header = ['name', 'url', 'email', 'username', 'password', 'note', 'totp', 'vault'];
	fputcsv($handle, $header);

	foreach ($rows as $row) {
		fputcsv($handle, [
			$row['name'],
			$row['url'],
			$row['email'],
			$row['username'],
			$row['password'],
			$row['note'],
			$row['totp'],
			$row['vault'],
		]);
	}

	fclose($handle);
}

final class ProtoReader
{
	private string $data;
	private int $length;
	private int $position = 0;

	public function __construct(string $data)
	{
		$this->data = $data;
		$this->length = strlen($data);
	}

	public function isEof(): bool
	{
		return $this->position >= $this->length;
	}

	public function readVarint(): int
	{
		$result = 0;
		$shift = 0;

		for ($i = 0; $i < 10; $i++) {
			if ($this->isEof()) {
				throw new RuntimeException('Unexpected end of data while reading varint.');
			}

			$byte = ord($this->data[$this->position++]);
			$result |= (($byte & 0x7F) << $shift);

			if (($byte & 0x80) === 0) {
				return $result;
			}

			$shift += 7;
		}

		throw new RuntimeException('Varint is too long.');
	}

	public function readLengthDelimited(): string
	{
		$length = $this->readVarint();
		if ($length < 0 || ($this->position + $length) > $this->length) {
			throw new RuntimeException('Length-delimited field exceeds payload bounds.');
		}

		$value = substr($this->data, $this->position, $length);
		$this->position += $length;
		return $value;
	}

	public function skipByWireType(int $wireType): void
	{
		if ($wireType === 0) {
			$this->readVarint();
			return;
		}

		if ($wireType === 1) {
			$this->skipBytes(8);
			return;
		}

		if ($wireType === 2) {
			$length = $this->readVarint();
			$this->skipBytes($length);
			return;
		}

		if ($wireType === 5) {
			$this->skipBytes(4);
			return;
		}

		throw new RuntimeException("Unsupported wire type: {$wireType}");
	}

	private function skipBytes(int $count): void
	{
		if ($count < 0 || ($this->position + $count) > $this->length) {
			throw new RuntimeException('Skip exceeds payload bounds.');
		}

		$this->position += $count;
	}
}