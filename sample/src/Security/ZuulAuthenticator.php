<?php
declare(strict_types=1);

namespace App\Security;

use App\OAuth2\Token;
use App\OAuth2\TokenManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use OAuth2Zuul\ZuulUser;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Symfony Authenticator implementation using the Zuul OAuth 2.0 Identity Provider.
 */
class ZuulAuthenticator extends OAuth2Authenticator implements AuthenticationEntrypointInterface {
	/**
	 * IdP response check route name.
	 */
	public const ROUTE_CHECK = 'auth_zuul_check';

	/**
	 * Key used in config/packages/knpu_oauth2_client.yaml.
	 */
	public const CLIENT_KEY = 'zuul';

	/**
	 * Parameter name of the list of scopes to request used in config/services.yaml.
	 */
	protected const SCOPES_KEY = 'zuul.scopes';

	/**
	 * Login page route name.
	 */
	protected const ROUTE_LOGIN_PAGE = 'index';

	/**
	 * ZuulAuthenticator constructor.
	 *
	 * @param ClientRegistry        $clientRegistry registry of OAuth 2.0 clients
	 * @param RouterInterface       $router         framework router
	 * @param UserProvider          $userProvider   User Entity provider
	 * @param TokenManagerInterface $tokenManager   OAuth 2.0 token manager
	 * @param string[]              $scopes         scopes to request from the IdP
	 */
	public function __construct(
		/**
		 * Registry of OAuth 2.0 clients.
		 */
		protected ClientRegistry $clientRegistry,

		/**
		 * Framework router.
		 */
		protected RouterInterface $router,

		/**
		 * User Entity provider.
		 */
		protected UserProvider $userProvider,

		/**
		 * OAuth 2.0 token manager.
		 */
		protected TokenManagerInterface $tokenManager,

		/**
		 * List of scopes to request from the Identity Provider.
		 *
		 * @var string[]
		 */
		#[Autowire(param: self::SCOPES_KEY)]
		protected array $scopes
	) {
	}

	/**
	 * @inheritdoc
	 */
	public function supports(Request $request): ?bool {
		return $request->attributes->get('_route') === self::ROUTE_CHECK;
	}

	/**
	 * @inheritdoc
	 */
	public function authenticate(Request $request): Passport {
		$client = $this->clientRegistry->getClient(self::CLIENT_KEY);
		$accessToken = $this->fetchAccessToken($client);

		return new SelfValidatingPassport(
			new UserBadge($accessToken->getToken(), function () use ($accessToken, $client) {
				/** @var ZuulUser $zuulUser */
				$zuulUser = $client->fetchUserFromToken($accessToken);

				/** @var User $user */
				$user = $this->userProvider->loadUserByIdentifier($zuulUser->getId());

				$token = new Token($accessToken->getToken(), $accessToken->getRefreshToken());

				$this->tokenManager->saveToken($user, $token);

				return $user;
			})
		);
	}

	/**
	 * @inheritdoc
	 */
	public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response {
		// let \App\Controller\SecurityController::checkAction() handle success
		return null;
	}

	/**
	 * @inheritdoc
	 */
	public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response {
		$this->saveAuthenticationErrorToSession($request, $exception);

		$path = $this->router->generate(self::ROUTE_LOGIN_PAGE);
		return new RedirectResponse($path, Response::HTTP_FOUND);
	}
	
	/**
	 * @inheritdoc
	 */
	public function start(Request $request, AuthenticationException $authException = null): Response {
		return $this->clientRegistry
		            ->getClient(self::CLIENT_KEY)
					->redirect($this->scopes, []);
	}
}