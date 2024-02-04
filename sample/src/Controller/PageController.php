<?php
declare(strict_types=1);

namespace App\Controller;

use App\OAuth2\TokenManagerInterface;
use App\Service\UsermapService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class PageController extends AbstractController {
	/**
	 * PageController constructor.
	 *
	 * @param AuthenticationUtils   $authUtils         security errors extractor
	 * @param TokenManagerInterface $oauthTokenManager OAuth 2.0 token manager
	 * @param UsermapService        $usermap           Usermap service
	 */
	public function __construct(
		/**
		 * Security errors extractor.
		 */
		protected AuthenticationUtils $authUtils,

		/**
		 * OAuth 2.0 token manager.
		 */
		protected TokenManagerInterface $oauthTokenManager,

		/**
		 * KOSapi service.
		 */
		protected UsermapService $usermap
	) {
	}

	#[Route('/', name: 'index')]
	public function indexPage(): Response {
		$authException = $this->authUtils->getLastAuthenticationError();

		if ($authException !== null) {
			$authError = sprintf('%s: %s', get_class($authException), $authException->getMessage());
		} else {
			$authError = null;
		}

		return $this->render('index.html.twig', [
			'auth_error' => $authError
		]);
	}

	#[Route('/user', name: 'user')]
	#[IsGranted('ROLE_USER')]
	public function userPage(): Response {
		$user = $this->getUser();

		$info = $this->usermap->fetchPerson($user, $user->getUserIdentifier());

		return $this->render('user.html.twig', [
			'username' => $user->getUserIdentifier(),
			'token' => $this->oauthTokenManager->getToken($user),
			'info' => $info
		]);
	}
}