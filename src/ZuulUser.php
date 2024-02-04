<?php
declare(strict_types=1);

namespace OAuth2Zuul;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * OAuth 2.0 Resource Owner information.
 */
class ZuulUser implements ResourceOwnerInterface {
	/**
	 * CTU username.
	 */
	protected string $username;

	/**
	 * ZuulUser constructor.
	 *
	 * @param string $username CTU username
	 */
	public function __construct(string $username) {
		$this->username = $username;
	}

	/**
	 * Returns CTU username.
	 *
	 * @return string
	 */
	public function getId(): mixed {
		return $this->username;
	}
	
	/**
	 * @inheritdoc
	 */
	public function toArray(): array {
		return [
			'username' => $this->username
		];
	}
}