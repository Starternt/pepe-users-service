<?php

declare(strict_types=1);

namespace App\Controller\Action;

use ApiPlatform\Core\Bridge\Symfony\Validator\Exception\ValidationException;
use App\Entity\User;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

final class RegisterAction extends AbstractController
{
    public function __construct(
        private readonly ValidatorInterface $validator,
        private readonly UserPasswordHasherInterface $passwordHasher
    ) {
    }

    public function __invoke(User $data): User
    {
        $validationErrors = $this->validator->validate($data);
        if ($validationErrors->count() > 0) {
            throw new ValidationException($validationErrors);
        }

        $data->setPassword($this->passwordHasher->hashPassword($data, $data->getPassword()));

        return $data;
    }
}
