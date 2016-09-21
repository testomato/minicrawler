<?php
$tests = [
	1 => function () {
		$userAgent = 'duck & dog';
		check_result_for_path(
			'/user-agent', ['-A' => $userAgent],
			[
				function ($result) use ($userAgent) {
					return [$userAgent, $result['user-agent'], 'Expected User Agent'];
				}
			]
		);
	},
	2 => function () {
		check_result_for_path(
			'/headers', ['-w' => 'X-Duck: Dog'],
			[
				function ($result) {
					return ['Dog', @$result['headers']['X-Duck'], 'Expected header X-Duck'];
				},
				function ($result) {
					return ['*/*', @$result['headers']['Accept'], 'Expected header Accept'];
				}
			]
		);
	},
	3 => function () {
		check_result_for_path(
			'/post', ['-P' => 'duck=dog'],
			[
				function ($result) {
					return [['duck' => 'dog'], $result['form'], 'Expected POST data'];
				}
			]
		);
	},
	4 => function () {
		check_result_for_path(
			'/delete', ['-X DELETE', '-P' => 'duck=dog'],
			[
				function ($result) {
					return [['duck' => 'dog'], $result['form'], 'Expected DELETE data'];
				}
			]
		);
	},
	5 => function () {
		check_result_for_path(
			'/gzip', ['-g'],
			[
				function ($result) {
					return [true, $result['gzipped'], 'Expected gzipped response'];
				}
			]
		);
	},
	6 => function () {
		check_result_for_path(
			'/status/418', [],
			[
				function ($result, $headers) {
					return [418, (int)$headers['Status'], 'Expected status'];
				}
			]
		);
	},
	7 => function () {
		check_result_for_path(
			'/redirect/9', ['-t30'],
			[
				function ($result, $headers) {
					return [9, count($headers['Redirect-info']), 'Expected redirects'];
				}
			]
		);
	},
	8 => function () {
		check_result_for_path(
			'/absolute-redirect/9', ['-t30'],
			[
				function ($result, $headers) {
					return [9, count($headers['Redirect-info']), 'Expected redirects'];
				}
			]
		);
	},
	9 => function () {
		check_result_for_path(
			'/cookies', ['-b' => host() . "\t0\t/\t0\t9999999999\tduck\tdog\n"],
			[
				function ($result) {
					return [['duck' => 'dog'], $result['cookies'], 'Expected cookies'];
				}
			]
		);
	},
	10 => function () {
		check_result_for_path(
			'/cookies/set?duck=dog', [],
			[
				function ($result, $headers) {
					return ["duck\tdog", substr($headers['Cookies'][0], -8), 'Expected cookies'];
				}
			]
		);
	},
	11 => function () {
		check_result_for_path(
			'/basic-auth/duck/dog', ['-u' => 'duck', '-pdog'],
			[
				function ($result) {
					return [true, $result['authenticated'], 'Expected authenticated'];
				},
				function ($result) {
					return ['duck', $result['user'], 'Expected authenticated user'];
				}
			]
		);
	},
	12 => function () {
		check_result_for_path(
			'/digest-auth/auth/duck/dog', ['-u' => 'duck', '-pdog'],
			[
				function ($result) {
					return [true, $result['authenticated'], 'Expected authenticated'];
				}
			]
		);
	},
];

