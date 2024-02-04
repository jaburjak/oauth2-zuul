<?php
declare(strict_types=1);

namespace App\OAuth2;

/**
 * Container for OAuth 2.0 Access and Refresh Tokens.
 */
readonly class Token {
	/**
	 * Token constructor.
	 *
	 * @param string $accessToken  Access Token
	 * @param string $refreshToken Refresh Token
	 */
	public function __construct(
		/**
		 * OAuth 2.0 Access Token.
		 */
		public string $accessToken,

		/**
		 * OAuth 2.0 Refresh Token.
		 */
		public ?string $refreshToken
	) {
	}
}