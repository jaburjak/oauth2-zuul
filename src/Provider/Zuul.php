<?php
declare(strict_types=1);

namespace OAuth2Zuul\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use OAuth2Zuul\ZuulUser;
use Psr\Http\Message\ResponseInterface;
use UnexpectedValueException;

/**
 * Zuul OAuth 2.0 provider.
 */
class Zuul extends AbstractProvider {
	/**
	 * Authorization endpoint path.
	 */
	protected const AUTHORIZATION_URL = '/oauth/authorize';

	/**
	 * Access token endpoint path.
	 */
	protected const ACCESS_TOKEN_URL = '/oauth/oauth/token';

	/**
	 * Resource owner details endpoint path.
	 */
	protected const OWNER_DETAILS_URL = '/api/v1/tokeninfo';

	/**
	 * Scope used to request resource owner details.
	 */
	protected const TOKENINFO_SCOPE = 'urn:zuul:oauth:oaas:tokeninfo';

	/**
	 * Default value of the `base_url` option.
	 */
	protected const DEFAULT_BASE_URL = 'https://auth.fit.cvut.cz';

	/**
	 * Identity Provider base URL.
	 *
	 * This will be prepended to paths in *_URL constants.
	 */
	protected string $baseUrl;

	/**
	 * @inheritdoc
	 */
	public function __construct(array $options = [], array $collaborators = []) {
		parent::__construct($options, $collaborators);

		$this->baseUrl = $options['base_url'] ?? self::DEFAULT_BASE_URL;
	}

	/**
	 * @inheritdoc
	 */
	public function getBaseAuthorizationUrl(): string {
		return $this->baseUrl.self::AUTHORIZATION_URL;
	}

	/**
	 * @inheritdoc
	 */
	public function getBaseAccessTokenUrl(array $params): string {
		return $this->baseUrl.self::ACCESS_TOKEN_URL;
	}

	/**
	 * @inheritdoc
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token): string {
		return sprintf(
			'%s%s?token=%s',
			$this->baseUrl,
			self::OWNER_DETAILS_URL,
			urlencode($token->getToken())
		);
	}

	/**
	 * @inheritdoc
	 */
	protected function getDefaultScopes(): array {
		return [self::TOKENINFO_SCOPE];
	}

	/**
	 * @inheritdoc
	 */
	protected function getScopeSeparator(): string {
		return ' ';
	}

	/**
	 * @inheritdoc
	 */
	protected function checkResponse(ResponseInterface $response, $data): void {
		if (isset($data['error'])) {
			throw new IdentityProviderException($data['error_description'] ?? $data['error'], 0, $data);
		}
	}

	/**
	 * @inheritdoc
	 */
	protected function createResourceOwner(array $response, AccessToken $token): ResourceOwnerInterface {
		if (!isset($response['user_id']) || $response['user_id'] === '') {
			throw new UnexpectedValueException('The Resource Owner information are missing the "user_id" field.');
		}

		return new ZuulUser((string) $response['user_id']);
	}
}