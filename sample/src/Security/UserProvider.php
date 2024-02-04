<?php
declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * User provider responsible for loading and constructing user entities.
 */
class UserProvider implements UserProviderInterface {
	/**
	 * @inheritdoc
	 */
	public function supportsClass(string $class): bool {
		return User::class === $class;
	}

	/**
	 * @inheritdoc
	 */
	public function loadUserByIdentifier(string $identifier): UserInterface {
		// TODO: fetch an existing user from the database or persist them if logging in for the first time
		// 
		// $em = $this->entityManagerRepository->getManagerForClass(User::class);
		//
		// $user = $em->getRepository(User::class)
		//            ->findByCtuUsername($identifier);
		// 
		// if ($user === null) {
		//     $user = new User();
		//     $user->setCtuUsername($identifier);
		//     
		//     $em->persist($user);
		//     $em->flush();
		// }
		// 
		// return $user;

		return new User($identifier);
	}

	/**
	 * @inheritdoc
	 */
	public function refreshUser(UserInterface $user): UserInterface {
		return $this->loadUserByIdentifier($user->getUserIdentifier());
	}
}