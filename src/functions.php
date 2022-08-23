<?php

namespace Kelunik\OAuthCli;

use Amp\ByteStream\ReadableBuffer;
use Amp\DeferredFuture;
use Amp\Http\Server\DefaultErrorHandler;
use Amp\Http\Server\Request;
use Amp\Http\Server\RequestHandler\ClosureRequestHandler;
use Amp\Http\Server\Response;
use Amp\Http\Server\SocketHttpServer;
use Amp\Socket\InternetAddress;
use Kelunik\OAuth\Provider;
use Psr\Log\NullLogger;

function authenticate(Provider $provider, int $localHttpPort = 1337): string
{
    $state = \bin2hex(\random_bytes(32));

    $deferred = new DeferredFuture;
    $future = $deferred->getFuture();

    $server = new SocketHttpServer(new NullLogger());
    $server->expose(new InternetAddress('127.0.0.1', $localHttpPort));

    $requestHandler = new ClosureRequestHandler(function (Request $request) use (&$deferred, $state): Response {
        if (!$deferred) {
            return new Response();
        }

        $query = $request->getUri()->getQuery();
        \parse_str($query, $params);

        if (hash_equals($params["state"], $state)) {
            $deferred?->complete($params['code']);
            $deferred = null;

            return new Response(
                200,
                [],
                new ReadableBuffer(file_get_contents(__DIR__ . "/../res/authentication-complete.html"))
            );
        }

        return new Response();
    });

    $server->start($requestHandler, new DefaultErrorHandler());

    exec("open " . escapeshellarg($provider->getAuthorizationUrl($state)));

    $code = $future->await();

    $server->stop();

    return $provider->exchangeAccessTokenForCode($code);
}