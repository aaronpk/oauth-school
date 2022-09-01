<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class RefreshTokenController extends ExerciseController {

  use AuthorizationFlowTrait;

  protected $pageTitle = 'Refresh Tokens';
  protected $baseRoute = 'refresh';

  public function index(Request $request): Response {

    if($request->query->get('reset')) {
      $this->session->remove('refresh_token_response_1');
      $this->session->remove('authorizationURLSuccess');
      $this->session->remove('authorizationURL');
    }

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/refresh-token.html.twig', [
      'page_title' => $this->pageTitle,
      'issuer' => $issuer,
      'scopes' => $scopes,
      'base_route' => $this->baseRoute,
      'confidential_client' => true,
    ]);
  }

  protected function _additionalAuthzChecks($authorizationURL, $queryParams, $scopesRequested) {

    if(!in_array('offline_access', $scopesRequested)) {
      return $this->_respondWithError($this->baseRoute,
        'Make sure you include the offline_access scope in the request',
        $authorizationURL);
    }

    return true;
  }

  public function save(Request $request): Response {

    $redirectToRoute = $this->baseRoute;

    if($errorResponse = $this->_initialAccessTokenChecks($request, [
      'allowRefreshToken' => true
    ])) {
      return $errorResponse;
    }

    // Make sure the response also includes a refresh token
    $response = json_decode($this->tokenResponse, true);

    if(!isset($response['refresh_token'])) {
      return $this->_respondWithError($redirectToRoute,
        'The response from the token endpoint did not contain a refresh token. Double check that you\'ve enabled Offline Access for the API, and make sure you include the offline_access scope in the authorization request.',
        $this->tokenResponse);
    }

    $this->session->set('refresh_token_response_1', $this->tokenString);
    $this->session->set('authorizationURLSuccess', true);

    // Everything checked out, log a success for this step and continue
    return $this->_respondWithSuccess(
      $this->baseRoute,
      'Great! You got a refresh token! Now use it to get a new access token, and paste the new response from the token endpoint below.',
      $this->claimsString
    );
  }

  public function refresh(Request $request): Response {

    if($errorResponse = $this->_initialAccessTokenChecks($request, [
      'allowRefreshToken' => true
    ])) {
      return $errorResponse;
    }

    $this->session->set('authorizationURLSuccess', true);

    // Check that the access token in this response is not the same as the previous one
    $previousAccessToken = $this->session->get('refresh_token_response_1');

    if($previousAccessToken == $this->tokenString) {
      return $this->_respondWithError($this->baseRoute,
        'That looks like the same access token as before. Make sure you use the refresh token and you should get back a different access token.',
        $this->tokenResponse);
    }

    $this->session->remove('refresh_token_response_1');
    $this->session->set('complete_refresh', true);
    $this->session->remove('authorizationURLSuccess');
    $this->session->remove('authorizationURL');

    return $this->_respondWithSuccess(
      $this->baseRoute,
      'Success! You used the refresh token to get a new access token back in the response!',
      $this->claimsString
    );
  }

}
