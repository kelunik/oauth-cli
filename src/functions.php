<?php

namespace Kelunik\OAuthCli;

use Aerys\Host;
use Aerys\Request;
use Aerys\Response;
use Amp\Deferred;
use Amp\Loop;
use Amp\Promise;
use Kelunik\OAuth\Provider;
use Psr\Log\NullLogger;
use function Aerys\initServer;
use function Amp\call;

function authenticate(Provider $provider, int $localHttpPort = 1337): Promise {
    return call(function () use ($provider, $localHttpPort) {
        $state = \bin2hex(\random_bytes(32));

        $deferred = new Deferred;
        $deferredPromise = $deferred->promise();

        $host = (new Host)
            ->name("localhost")
            ->expose("127.0.0.1", $localHttpPort)
            ->use(function (Request $request, Response $response) use ($state, &$deferred) {
                if (!$deferred) {
                    return;
                }

                if (hash_equals($request->getParam("state"), $state)) {
                    yield $response->end(file_get_contents(__DIR__ . "/../res/authentication-complete.html"));

                    Loop::defer(function () use ($request, &$deferred) {
                        $deferred->resolve($request->getParam("code"));
                        $deferred = null;
                    });
                }
            });

        $server = initServer(new NullLogger, [$host]);
        yield $server->start();

        exec("xdg-open " . escapeshellarg($provider->getAuthorizationUrl($state)) . " 2>/dev/null");

        $code = yield $deferredPromise;

        yield $server->stop();

        return $provider->exchangeAccessTokenForCode($code);
    });
}