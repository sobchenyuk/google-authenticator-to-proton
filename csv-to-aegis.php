<?php

declare(strict_types=1);

main($argv);

function main(array $argv): void
{
	$options = parseArguments($argv);

	if (!empty($options['help']) || $options['input'] === null) {
		printUsage();
		return;
	}

	if (!is_file($options['input'])) {
		fwrite(STDERR, "Input file not found: {$options['input']}\n");
		exit(1);
	}

	$handle = fopen($options['input'], 'rb');
	if ($handle === false) {
		fwrite(STDERR, "Unable to open input file: {$options['input']}\n");
		exit(1);
	}

	$header = fgetcsv($handle);
	if ($header === false) {
		fwrite(STDERR, "Input file is empty.\n");
		exit(1);
	}

	$header = array_map(static fn(string $col): string => strtolower(trim($col)), $header);
	$colIndex = array_flip($header);

	foreach (['name', 'totp'] as $required) {
		if (!isset($colIndex[$required])) {
			fwrite(STDERR, "Input CSV is missing required column: {$required}\n");
			exit(1);
		}
	}

	$entries = [];
	$stats = [
		'rows' => 0,
		'exported' => 0,
		'skipped' => 0,
	];

	while (($row = fgetcsv($handle)) !== false) {
		$stats['rows']++;

		if (count($row) === 1 && trim((string)$row[0]) === '') {
			continue;
		}

		$get = static function (array $row, array $colIndex, string $name): string {
			$index = $colIndex[$name] ?? null;
			if ($index === null || !isset($row[$index])) {
				return '';
			}
			return trim((string)$row[$index]);
		};

		$name = $get($row, $colIndex, 'name');
		$email = $get($row, $colIndex, 'email');
		$username = $get($row, $colIndex, 'username');
		$totpUri = $get($row, $colIndex, 'totp');

		if ($totpUri === '') {
			$stats['skipped']++;
			fwrite(STDERR, "Row " . ($stats['rows'] + 1) . ": empty totp field, skipping ({$name}).\n");
			continue;
		}

		$entry = parseOtpauthUri($totpUri);
		if ($entry === null) {
			$stats['skipped']++;
			fwrite(STDERR, "Row " . ($stats['rows'] + 1) . ": could not parse totp URI, skipping ({$name}).\n");
			continue;
		}

		$account = $email !== '' ? $email : $username;
		$entryName = $account !== '' ? $account : ($entry['label'] !== '' ? $entry['label'] : $name);
		$issuer = $entry['issuer'];

		$info = [
			'secret' => $entry['secret'],
			'algo' => $entry['algorithm'],
			'digits' => $entry['digits'],
		];

		if ($entry['type'] === 'hotp') {
			$info['counter'] = $entry['counter'];
		} else {
			$info['period'] = $entry['period'];
		}

		$entries[] = [
			'type' => $entry['type'],
			'uuid' => generateUuidV4(),
			'name' => $entryName,
			'issuer' => $issuer,
			'note' => '',
			'favorite' => false,
			'icon' => null,
			'info' => $info,
			'groups' => [],
		];

		$stats['exported']++;
	}

	fclose($handle);

	writeAegisJson($options['out'], $entries);

	echo "Done.\n";
	echo "Rows read: {$stats['rows']}\n";
	echo "Entries exported: {$stats['exported']}\n";
	echo "Rows skipped: {$stats['skipped']}\n";
	echo "Output file: {$options['out']}\n";
}

function parseArguments(array $argv): array
{
	$options = [
		'input' => null,
		'out' => 'aegis-export.json',
		'help' => false,
	];

	for ($i = 1, $count = count($argv); $i < $count; $i++) {
		$arg = $argv[$i];
		switch ($arg) {
			case '--input':
				$options['input'] = $argv[$i + 1] ?? null;
				$i++;
				break;
			case '--out':
				$options['out'] = $argv[$i + 1] ?? $options['out'];
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
	echo "  php csv-to-aegis.php --input combined.csv [--out aegis-export.json]\n";
	echo "\n";
	echo "Converts a Proton Pass style CSV (columns: name,url,email,username,password,note,totp,vault)\n";
	echo "into an unencrypted Aegis vault JSON file, ready to import into Proton Authenticator\n";
	echo "via Settings -> Import -> Aegis Authenticator.\n";
}

/**
 * Parses an otpauth://totp/... or otpauth://hotp/... URI into its components.
 * Returns null if the URI cannot be parsed or is missing a secret.
 */
function parseOtpauthUri(string $uri): ?array
{
	$parts = parse_url($uri);
	if ($parts === false || ($parts['scheme'] ?? '') !== 'otpauth') {
		return null;
	}

	$type = strtolower((string)($parts['host'] ?? ''));
	if (!in_array($type, ['totp', 'hotp'], true)) {
		return null;
	}

	$path = $parts['path'] ?? '';
	$label = rawurldecode(ltrim($path, '/'));

	$issuerFromLabel = '';
	$accountFromLabel = $label;
	if (str_contains($label, ':')) {
		[$issuerFromLabel, $accountFromLabel] = array_map('trim', explode(':', $label, 2));
	}

	$query = [];
	if (isset($parts['query'])) {
		parse_str($parts['query'], $query);
	}

	$secret = (string)($query['secret'] ?? '');
	if ($secret === '') {
		return null;
	}

	$algorithm = strtoupper((string)($query['algorithm'] ?? 'SHA1'));
	if (!in_array($algorithm, ['SHA1', 'SHA256', 'SHA512', 'MD5'], true)) {
		$algorithm = 'SHA1';
	}

	$digits = (int)($query['digits'] ?? 6);
	if (!in_array($digits, [6, 8], true)) {
		$digits = 6;
	}

	$period = (int)($query['period'] ?? 30);
	if ($period <= 0) {
		$period = 30;
	}

	$counter = (int)($query['counter'] ?? 0);

	$issuer = (string)($query['issuer'] ?? $issuerFromLabel);

	return [
		'type' => $type,
		'secret' => $secret,
		'algorithm' => $algorithm,
		'digits' => $digits,
		'period' => $period,
		'counter' => $counter,
		'issuer' => trim($issuer),
		'label' => trim($accountFromLabel),
	];
}

function generateUuidV4(): string
{
	$data = random_bytes(16);
	$data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
	$data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
	$hex = bin2hex($data);

	return sprintf(
		'%s-%s-%s-%s-%s',
		substr($hex, 0, 8),
		substr($hex, 8, 4),
		substr($hex, 12, 4),
		substr($hex, 16, 4),
		substr($hex, 20, 12)
	);
}

function writeAegisJson(string $path, array $entries): void
{
	$vault = [
		'version' => 1,
		'header' => [
			'slots' => null,
			'params' => null,
		],
		'db' => [
			'version' => 3,
			'entries' => $entries,
		],
	];

	$json = json_encode($vault, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	if ($json === false) {
		throw new RuntimeException('Failed to encode Aegis JSON: ' . json_last_error_msg());
	}

	if (file_put_contents($path, $json) === false) {
		throw new RuntimeException("Unable to write output file: {$path}");
	}
}