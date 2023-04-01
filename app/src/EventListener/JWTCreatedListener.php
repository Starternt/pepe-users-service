<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\User;
use Lexik\Bundle\JWTAuthenticationBundle\Event\JWTCreatedEvent;
use Symfony\Component\HttpFoundation\RequestStack;

final class JWTCreatedListener
{
    public function __construct(private readonly RequestStack $requestStack, private readonly string $jwtIss)
    {
    }

    public function onJWTCreated(JWTCreatedEvent $event): void
    {
        /** @var User $user */
        $user = $event->getUser();

        $payload = $event->getData();
        $payload['user_id'] = $user->getId();

        $event->setData($payload);

        $header = $event->getHeader();
        $header['iss'] = $this->jwtIss;

        $event->setHeader($header);
    }
}
