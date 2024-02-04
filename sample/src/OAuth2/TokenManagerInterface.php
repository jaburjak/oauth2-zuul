<?php
declare(strict_types=1);

namespace App\OAuth2;

use App\Security\User;

/**
 * Stores, retrieves and refreshes OAuth 2.0 Tokens of a particular user.
 */
interface TokenManagerInterface {
	/**
	 * Stores the OAuth 2.0 Access and Refresh Tokens of the given user.
	 *
	 * @param User  $user  user entity
	 * @param Token $token OAuth 2.0 tokens
	 */
	public function saveToken(User $user, Token $token): void;

	/**
	 * Retrieves the OAuth 2.0 Access Token of the given user.
	 *
	 * @param User $user user entity
	 * @return Token|null Access Token or `null` if not available
	 */
	public function getToken(User $user): ?Token;

	/**
	 * Refreshes the OAuth 2.0 Access Token.
	 *
	 * This method will automatically store the refreshed token.
	 *
	 * @param User $user user entity
	 * @return Token refreshed Access Token
	 */
	public function refreshToken(User $user): Token;
}