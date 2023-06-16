<?php
return [
	function () {
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
	function () {
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
	function () {
		check_result_for_path(
			'/post', ['-P' => 'duck=dog'],
			[
				function ($result) {
					return [['duck' => 'dog'], $result['form'], 'Expected POST data'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/delete', ['-X DELETE', '-P' => 'duck=dog'],
			[
				function ($result) {
					return [['duck' => 'dog'], $result['form'], 'Expected DELETE data'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/gzip', ['-g'],
			[
				function ($result) {
					return [true, $result['gzipped'], 'Expected gzipped response'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/status/418', [],
			[
				function ($result, $headers) {
					return [418, (int)$headers['Status'], 'Expected status'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/redirect/9', ['-t30'],
			[
				function ($result, $headers) {
					return [9, count($headers['Redirect-info']), 'Expected redirects'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/absolute-redirect/9', ['-t30'],
			[
				function ($result, $headers) {
					return [9, count($headers['Redirect-info']), 'Expected redirects'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/cookies', ['-b' => host() . "\t0\t/\t0\t9999999999\tduck\tdog\n"],
			[
				function ($result) {
					return [['duck' => 'dog'], $result['cookies'], 'Expected cookies'];
				}
			]
		);
	},
	function () {
		check_result_for_path(
			'/cookies/set?duck=dog', [],
			[
				function ($result, $headers) {
					return ["duck\tdog", substr($headers['Cookies'][0], -8), 'Expected cookies'];
				}
			]
		);
	},
	function () {
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
	function () {
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

