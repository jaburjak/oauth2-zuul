<?php
declare(strict_types=1);

namespace App\Service;

use App\OAuth2\Token;
use App\OAuth2\TokenManagerInterface;
use App\Security\User;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Contracts\HttpClient\Exception\DecodingExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use UnexpectedValueException;

/**
 * Usermap service.
 */
class UsermapService {
	/**
	 * Base API URL.
	 */
	protected const BASE_URL = 'https://kosapi.fit.cvut.cz/usermap/v1';

	/**
	 * UsermapService constructor.
	 *
	 * @param HttpClientInterface   $http         HTTP client
	 * @param TokenManagerInterface $tokenManager OAuth 2.0 token manager
	 */
	public function __construct(
		/**
		 * HTTP client.
		 */
		protected HttpClientInterface $http,

		/**
		 * OAuth 2.0 token manager.
		 */
		protected TokenManagerInterface $tokenManager
	) {
	}

	/**
	 * Returns information about the given user.
	 *
	 * @param User   $authority user that is requesting the information
	 * @param string $username  requested username
	 * @return string user information
	 */
	public function fetchPerson(User $authority, string $username): string {
		$path = sprintf('/people/%s', urlencode($username));

		$response = $this->request('GET', $path, $authority);

		if ($response->getStatusCode() !== Response::HTTP_OK) {
			throw new UnexpectedValueException(sprintf(
				'Usermap API returned an unexpected response code %d.',
				$response->getStatusCode()
			));
		}

		return json_encode($response->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
	}

	/**
	 * Sends an HTTP request to Usermap API.
	 *
	 * @param string $method    HTTP method
	 * @param string $path      API path
	 * @param User   $authority user that is sending the request
	 * @return ResponseInterface HTTP response
	 */
	protected function request(string $method, string $path, User $authority): ResponseInterface {
		$token = $this->tokenManager->getToken($authority);

		$url = self::BASE_URL . $path;

		$options = [
			'headers' => [
				'Authorization' => self::buildAuthorizationHeader($token)
			]
		];

		$response = $this->http->request($method, $url, $options);

		if (self::hasTokenExpired($response)) {
			$token = $this->tokenManager->refreshToken($authority);

			$options['headers']['Authorization'] = self::buildAuthorizationHeader($token);

			$response = $this->http->request($method, $url, $options);
		}

		return $response;
	}

	/**
	 * Assembles the HTTP Authorization header.
	 *
	 * @param  Token  $token OAuth 2.0 used for authentication
	 * @return string header content
	 */
	protected static function buildAuthorizationHeader(Token $token) : string {
		return sprintf('Bearer %s', $token->accessToken);
	}

	/**
	 * Checks whether the API response indicates that the OAuth 2.0 Access Token has expired.
	 *
	 * @param  ResponseInterface $response API response
	 * @return boolean `true` if Access Token has expired, `false` otherwise
	 */
	protected static function hasTokenExpired(ResponseInterface $response) : bool {
		if ($response->getStatusCode() === Response::HTTP_UNAUTHORIZED) {
			try {
				$error = $response->toArray(false)['error'] ?? null;

				return $error === 'invalid_token';
			} catch (DecodingExceptionInterface $e) {
				// response is not a JSON, noop
			}
		}

		return false;
	}
}