<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;


class OpenIDFlowController extends ExerciseController {

  use AuthorizationFlowTrait;

  protected $pageTitle = 'OpenID Connect Flow';
  protected $baseRoute = 'openid';

  protected $requireCustomScopeInAuthz = false;

  public function index(Request $request): Response {

    if($request->query->get('reset')) {
      $this->session->remove('openid_claims');
    }

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/openid.html.twig', [
      'page_title' => $this->pageTitle,
      'issuer' => $issuer,
      'scopes' => $scopes,
      'base_route' => $this->baseRoute,
      'id_token' => $this->session->get('openid_idtoken'),
    ]);
  }

  protected function _additionalAuthzChecks($authorizationURL, $queryParams, $scopesRequested) {

    if(!in_array('openid', $scopesRequested)) {
      return $this->_respondWithError($this->baseRoute,
        'Make sure you include the openid scope in the request',
        $authorizationURL);
    }

    if(count(array_intersect($scopesRequested, ['profile','email'])) != 2) {
      return $this->_respondWithError($this->baseRoute,
        'Make sure you include the profile and email scopes in the request in order to learn the user\'s profile information',
        $authorizationURL);
    }

    return true;
  }

  public function save(Request $request): Response {

    $tokenResponse = $this->tokenResponse = $request->request->get('tokenResponse');

    if(!$tokenResponse) {
      return $this->_respondWithError($this->baseRoute,
        'Please enter the full token response',
        $tokenResponse);
    }

    // Attempt to parse as JSON
    $response = json_decode($tokenResponse, true);

    if(!$response || !is_array($response)) {
      return $this->_respondWithError($this->baseRoute,
        'Make sure you enter the full response from the token endpoint, not just the ID token',
        $tokenResponse);
    }

    // Check that the response includes an ID token
    if(!isset($response['id_token'])) {
      return $this->_respondWithError($this->baseRoute,
        'The token response does not contain an ID token. Check for any error messages in the token response and try again.',
        $tokenResponse);
    }

    // Now parse the ID token

    $this->tokenString = $tokenString = $response['id_token'];

    if(!preg_match('/^(.+)\.(.+)\.(.+)$/', $tokenString, $match)) {
      return $this->_respondWithError($this->baseRoute,
        'The ID token returned does not look like a JWT.',
        $tokenString);
    }

    $this->header = $header = json_decode(base64_decode($match[1]), true);
    $this->claims = $claims = json_decode(base64_decode($match[2]), true);

    if(!$claims || !is_array($claims)) {
      return $this->_respondWithError($this->baseRoute,
        'Something went wrong trying to parse the claims in the token.',
        $tokenString);
    }

    $this->claimsString = $claimsString = json_encode($claims, JSON_PP);

    // Check for a sub claim
    if(!isset($claims['sub'])) {
      return $this->_respondWithError($this->baseRoute,
        'The ID token is missing the "sub" claim.',
        $claimsString);
    }

    // Now attempt to verify the token using the JWKs from the metadata URL
    try {
      $this->tokenData = $tokenData = JWT::decode($tokenString, JWK::parseKeySet($this->session->get('jwks')), ['RS256']);
    } catch(\Exception $e) {
      return $this->_respondWithError($this->baseRoute,
        'There was an error validating the JWT: '.$e->getMessage(),
        $claimsString);
    }

    // Check for the "name" and "email" claims
    if(!isset($claims['name']) || !isset($claims['email'])) {
      return $this->_respondWithError($this->baseRoute,
        'The ID token is missing the "name" and "email" claims. Make sure you requested the "profile" and "email" scopes in the request.',
        $claimsString);
    }

    $this->_updateEmailForIssuer($claims['email']);

    $this->session->set('openid_idtoken', $tokenString);
    $this->session->set('openid_claims', $claims);

    return $this->_respondWithSuccess(
      $this->baseRoute,
      'Great! Next you need to extract the claims component of the ID token to find the user\'s name and email address.',
      $this->claimsString
    );
  }

  public function claims(Request $request): Response {

    if(!$this->session->get('openid_claims')) {
      return $this->_respondWithError($this->baseRoute,
        'Make sure you finish the first part of the exercise first',
        '');
    }

    $claims = $this->session->get('openid_claims');

    $input = [
      'sub' => $request->request->get('openid_sub'),
      'email' => $request->request->get('openid_name'),
      'name' => $request->request->get('openid_name'),
      'claims' => $claims,
    ];

    if($claims['sub'] != $request->request->get('openid_sub')) {
      return $this->_respondWithError($this->baseRoute,
        'The subject you entered didn\'t match the one found in the ID token. Try again!',
        json_encode($input));
    }

    if($claims['email'] != $request->request->get('openid_email')) {
      return $this->_respondWithError($this->baseRoute,
        'The email you entered didn\'t match the one found in the ID token. Try again!',
        json_encode($input));
    }

    if($claims['name'] != $request->request->get('openid_name')) {
      return $this->_respondWithError($this->baseRoute,
        'The name you entered didn\'t match the one found in the ID token. Try again!',
        json_encode($input));
    }

    $this->session->set('openid_name', $claims['name']);
    $this->session->set('openid_email', $claims['email']);

    $this->session->set('complete_openid', true);

    return $this->_respondWithSuccess(
      $this->baseRoute,
      'Great work! You found the user\'s name and email address from the ID token!',
      $this->session->get('openid_idtoken')
    );
  }

}
