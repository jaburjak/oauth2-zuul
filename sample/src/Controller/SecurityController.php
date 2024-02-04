<?php
declare(strict_types=1);

namespace App\Controller;

use App\Security\ZuulAuthenticator;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Controller that handles redirection to and response from the Identity Provider.
 */
class SecurityController extends AbstractController {
	/**
	 * Key used in config/packages/knpu_oauth2_client.yaml.
	 */
	protected const CLIENT_KEY = 'zuul';

	/**
	 * Key used in config/packages/security.yaml.
	 */
	protected const FIREWALL_KEY = 'main';

	/**
	 * Default route to redirect to after successful authentication.
	 */
	protected const DEFAULT_REDIRECT = 'index';

	/**
	 * SecurityController constructor.
	 * @param AuthenticationEntryPointInterface $entrypoint authentication entrypoint
	 */
	public function __construct(
		/**
		 * Object responsible for redirecting to the Identity Provider.
		 */
		protected AuthenticationEntryPointInterface $entrypoint
	) {
	}

	/**
	 * Redirects the user to the Identity Provider.
	 *
	 * @param Request $request HTTP request
	 * @return Response HTTP response
	 */
	#[Route('/auth/login', name: 'auth_login')]
	public function loginAction(Request $request): Response {
		return $this->entrypoint->start($request);
	}

	/**
	 * Generates a response after successful authentication via the Identity Provider.
	 *
	 * The {@see \App\Security\Authenticator\ZuulAuthenticator::authenticate()} method will be executed when visiting
	 * this route. It is the authenticator’s responsibility to determine whether the user was authenticated
	 * successfully. This method will be executed only after the check successfully passes.
	 *
	 * @param Request $request HTTP request
	 * @return Response HTTP response
	 */
	#[Route('/auth/zuul/check', name: ZuulAuthenticator::ROUTE_CHECK)]
	public function checkAction(Request $request): Response {
		$previousUrl = $this->getPreviousUrl($request);

		if ($previousUrl !== null) {
			return $this->redirect($previousUrl, Response::HTTP_FOUND);
		} else {
			return $this->redirectToRoute(self::DEFAULT_REDIRECT);
		}
	}

	/**
	 * Provides a logout route.
	 *
	 * Body of this method should never be executed. Instead, Symfony will pick up the route when configured in
	 * security.yaml and perform the logout by itself.
	 *
	 * @return noreturn
	 */
	#[Route('/auth/logout', name: 'auth_logout')]
	public function logoutAction(): Response {
		throw new RuntimeException('Logout is not activated in security.yaml.');
	}

	/**
	 * Extracts URL the user tried to visit before authenticating.
	 *
	 * @param Request $request HTTP request
	 * @return string|null URL or `null`
	 */
	protected function getPreviousUrl(Request $request): ?string {
		if ($request->hasSession() && $request->getSession() instanceof SessionInterface) {
			return $request->getSession()->get(
				sprintf('_security.%s.target_path', self::FIREWALL_KEY)
			);
		} else {
			return null;
		}
	}
}