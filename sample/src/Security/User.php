<?php
declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * User entity.
 */
class User implements UserInterface {
	/**
	 * CTU username.
	 */
	protected string $username;

	/**
	 * Roles in the sample application.
	 *
	 * @var string[]
	 */
	protected array $roles = ['ROLE_USER'];

	/**
	 * OAuth 2.0 access token.
	 */
	protected ?string $accessToken = null;

	/**
	 * OAuth 2.0 refresh token.
	 */
	protected ?string $refreshToken = null;

	/**
	 * User constructor.
	 *
	 * @param string $username CTU username
	 */
	public function __construct(string $username) {
		$this->username = $username;
	}

	/**
	 * Returns OAuth 2.0 access token.
	 *
	 * @return string|null OAuth 2.0 access token
	 */
	public function getAccessToken(): ?string {
		return $this->accessToken;
	}

	/**
	 * Sets the OAuth 2.0 access token.
	 *
	 * @param string|null $accessToken access token
	 * @return $this
	 */
	public function setAccessToken(?string $accessToken): self {
		$this->accessToken = $accessToken;
		return $this;
	}

	/**
	 * Returns OAuth 2.0 refresh token.
	 *
	 * @return string|null OAuth 2.0 refresh token
	 */
	public function getRefreshToken(): ?string {
		return $this->refreshToken;
	}

	/**
	 * Sets the OAuth 2.0 refresh token.
	 *
	 * @param string|null $refreshToken refresh token
	 * @return $this
	 */
	public function setRefreshToken(?string $refreshToken): self {
		$this->refreshToken = $refreshToken;
		return $this;
	}

	/**
	 * @inheritdoc
	 */
	public function getUserIdentifier(): string {
		return $this->username;
	}

	/**
	 * @inheritdoc
	 */
	public function getRoles(): array {
		return $this->roles;
	}

	/**
	 * @inheritdoc
	 */
	public function eraseCredentials(): void {
		$this->accessToken = null;
		$this->refreshToken = null;
	}
}