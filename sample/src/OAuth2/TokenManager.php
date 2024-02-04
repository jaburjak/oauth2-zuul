<?php
declare(strict_types=1);

namespace App\OAuth2;

use App\Security\User;
use App\Security\ZuulAuthenticator;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2ClientInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use LogicException;
use RuntimeException;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Stores, retrieves and refreshes OAuth 2.0 Tokens of a particular user.
 *
 * In this implementation, tokens are stored in the session.
 */
class TokenManager implements TokenManagerInterface {
	/**
	 * Session key of the Access Token.
	 */
	protected const ACCESS_TOKEN = 'oauth2.access_token';

	/**
	 * Session key of the Refresh Token.
	 */
	protected const REFRESH_TOKEN = 'oauth2.refresh_token';

	/**
	 * TokenManager constructor.
	 *
	 * @param RequestStack   $requestStack   HTTP request stack
	 * @param ClientRegistry $clientRegistry registry of OAuth 2.0 clients
	 */
	public function __construct(
		/**
		 * HTTP request stack.
		 */
		protected RequestStack $requestStack,

		/**
		 * Registry of OAuth 2.0 clients.
		 */
		protected ClientRegistry $clientRegistry
	) {
	}

	/**
	 * @inheritdoc
	 */
	public function saveToken(User $user, Token $token): void {
		$user->setAccessToken($token->accessToken)
		     ->setRefreshToken($token->refreshToken);

		// TODO: Maybe we want to save OAuth 2.0 tokens in the database? It would also be necessary to remove null
		// assignment in User::eraseCredentials().
		// 
		// $this->entityManagerRepository
		//      ->getManagerForClass(User::class)
		//      ->flush();

		$session = $this->requestStack->getSession();

		$session->set(self::ACCESS_TOKEN, $token->accessToken);
		$session->set(self::REFRESH_TOKEN, $token->refreshToken);
	}

	/**
	 * @inheritdoc
	 */
	public function getToken(User $user): ?Token {
		// TODO: Maybe we want to save OAuth 2.0 tokens in the database? We would retrieve them from the user entity
		// instead of the session here.

		$session = $this->requestStack->getSession();

		$accessToken = $session->get(self::ACCESS_TOKEN);
		$refreshToken = $session->get(self::REFRESH_TOKEN);

		if ($accessToken === null) {
			return null;
		}

		return new Token($accessToken, $refreshToken);
	}

	/**
	 * @inheritdoc
	 */
	public function refreshToken(User $user): Token {
		$current = $this->getToken($user);

		if ($current === null || $current->refreshToken === null) {
			throw new LogicException('User does not have an OAuth 2.0 Refresh Token.');
		}

		try {
			$token = $this->getClient()
			              ->refreshAccessToken($current->refreshToken);
		} catch (IdentityProviderException $e) {
			throw new RuntimeException('Could not refresh OAuth 2.0 Access Token.', 0, $e);
		}

		$new = new Token($token->getToken(), $token->getRefreshToken());

		$this->saveToken($user, $new);

		return $new;
	}

	/**
	 * Returns OAuth 2.0 client.
	 *
	 * @return OAuth2ClientInterface OAuth 2.0 client
	 */
	protected function getClient(): OAuth2ClientInterface {
		return $this->clientRegistry->getClient(ZuulAuthenticator::CLIENT_KEY);
	}
}