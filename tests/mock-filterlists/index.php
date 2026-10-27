<?php

    /**
     * A mock of the FilterLists API (https://api.filterlists.com) for the test environment, so that the tests never
     * contact the real directory or the real lists. It serves the directory in directory.json with fixed responses:
     *
     *  - GET /lists, /tags, /languages and /syntaxes return the directory's lists (without their URLs), tags, languages
     *    and syntaxes
     *  - GET /lists/{id} returns a list with its URL, a file of lists/ served by this mock
     *  - GET /files/{name} returns that file of lists/
     *
     * Every host of the lists is reserved (.invalid), nothing in them ever resolves. Run with:
     * php -S 0.0.0.0:8080 index.php
     */

    function respond(int $status, string $body, string $type='application/json'): void
    {
        http_response_code($status);
        header('Content-Type: ' . $type);
        print($body);
    }

    $directory = json_decode(file_get_contents(__DIR__ . '/directory.json'), true);
    $base = 'http://' . ($_SERVER['HTTP_HOST'] ?? 'filterlists:8080');
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

    switch(true)
    {
        case $path === '/lists':
            respond(200, json_encode(array_map(function(array $list) { unset($list['file']); return $list; }, $directory['lists'])));
            break;

        case preg_match('#^/lists/(\d+)$#', $path, $matches) === 1:
            $list = array_values(array_filter($directory['lists'], fn(array $list) => $list['id'] === (int)$matches[1]))[0] ?? null;
            if($list === null)
            {
                respond(404, json_encode(['error' => 'Not found']));
                break;
            }

            $list['viewUrls'] = [['segmentNumber' => 1, 'primariness' => 1, 'url' => $base . '/files/' . $list['file']]];
            unset($list['file']);
            respond(200, json_encode($list, JSON_UNESCAPED_SLASHES));
            break;

        case in_array($path, ['/tags', '/languages', '/syntaxes'], true):
            respond(200, json_encode($directory[substr($path, 1)]));
            break;

        case preg_match('#^/files/([a-z0-9-]+\.txt)$#', $path, $matches) === 1 && is_file(__DIR__ . '/lists/' . $matches[1]):
            respond(200, file_get_contents(__DIR__ . '/lists/' . $matches[1]), 'text/plain');
            break;

        default:
            respond(404, json_encode(['error' => 'Not found']));
            break;
    }
