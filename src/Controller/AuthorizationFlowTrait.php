<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;
use Base64Url\Base64Url;

trait AuthorizationFlowTrait {

  public function index(Request $request): Response {

    if($request->query->get('reset')) {
      $this->session->remove('authorizationURLSuccess');
      $this->session->remove('authorizationURL');
    }

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/authorization-code.html.twig', [
      'page_title' => $this->pageTitle,
      'issuer' => $issuer,
      'scopes' => $scopes,
      'base_route' => $this->baseRoute,
      'confidential_client' => $this->confidentialClient,
    ]);
  }


  public function authz(Request $request): Response {

    $redirectToRoute = $this->baseRoute;

    $scopes = $this->session->get('scopes');

    $this->session->set('authorizationURLSuccess', false);

    $authorizationURL = trim($request->request->get('authorizationURL'));

    if(!$authorizationURL) {
      return $this->_respondWithError($redirectToRoute,
        'Please enter the authorization URL',
        $authorizationURL);
    }

    $authorizationURL = preg_replace('/[\s]+/', '', $authorizationURL);

    $this->session->set('authorizationURL', $authorizationURL);

    $url = parse_url($authorizationURL);

    // Check that it looks like a URL
    if(!$url) {
      return $this->_respondWithError($redirectToRoute,
        'Please enter a valid URL',
        $authorizationURL);
    }

    $authorizationEndpoint = $this->session->get('authorization_endpoint');

    // Check that the hostname matches the authorization server
    if(!isset($url['host']) || parse_url($authorizationEndpoint, PHP_URL_HOST) != $url['host']) {
      return $this->_respondWithError($redirectToRoute,
        'The host name of the URL you entered didn\'t match the host of your authorization server',
        $authorizationURL);
    }

    // Check that the path matches
    if(!isset($url['path']) || parse_url($authorizationEndpoint, PHP_URL_PATH) != $url['path']) {
      return $this->_respondWithError($redirectToRoute,
        'The base URL that you entered doesn\'t look like it matches your authorization endpoint',
        $authorizationURL);
    }

    // Check for all the required query string parameters
    if(empty($url['query'])) {
      return $this->_respondWithError($redirectToRoute,
        'Make sure you include the query string parameters describing your authorization request',
        $authorizationURL);
    }

    $provider = $this->_providerFromIssuer($this->session->get('issuer'));

    parse_str($url['query'], $query);

    $required = ['response_type', 'client_id', 'state', 'redirect_uri', 'code_challenge', 'code_challenge_method'];
    $optional = ['scope'];

    $missing = false;
    $invalid = false;
    foreach($required as $key) {
      if(empty($query[$key])) {
        $missing = true;
      } elseif(strpos($query[$key], '{') === 0) {
        $invalid = true;
      }
    }

    if($missing) {
      return $this->_respondWithError($redirectToRoute,
        'It looks like you are missing some query string parameters in the URL',
        $authorizationURL);
    }

    if($invalid) {
      return $this->_respondWithError($redirectToRoute,
        'Make sure you remove the placeholder brackets { } from the query string parameters!',
        $authorizationURL);
    }

    $diff = array_diff(array_keys($query), array_merge($required,$optional));

    if(count($diff)) {
      return $this->_respondWithError($redirectToRoute,
        'It looks like you have some extra query string parameters in your URL, or some are misspelled',
        $authorizationURL);
    }

    // check that the requested the custom scope they added
    $scopesRequested = !empty($query['scope']) ? explode(' ', $query['scope']) : [];

    if($provider == 'auth0')
      $this->requireCustomScopeInAuthz = false;

    if($this->requireCustomScopeInAuthz) {
      if(!array_intersect($scopesRequested, $scopes)) {
        return $this->_respondWithError($redirectToRoute,
          'Make sure you request one of the custom scopes you configured for this exercise',
          $authorizationURL);
      }
    }

    // TODO: possible future checks based on what people get wrong most often

    $addl = $this->_additionalAuthzChecks($authorizationURL, $query, $scopesRequested);
    if($addl !== true) {
      return $addl;
    }

    $this->session->set('authorizationURLSuccess', true);
    #$this->session->remove('authorizationURL');

    // Everything checked out, log a success
    return $this->_respondWithSuccess(
      $redirectToRoute,
      'Great! You built the URL, now you\'re ready to go log in. Click the login link to be taken to the authorization server and log in',
      $authorizationURL,
      ['loginURL' => $authorizationURL]
    );

  }

  private $tokenResponse;
  private $tokenString;
  private $tokenData;
  private $header;
  private $claimsString;
  private $claims;

  private function _initialAccessTokenChecks(Request $request, $opts=[]) {

    $scopes = $this->session->get('scopes');
    $provider = $this->_providerFromIssuer($this->session->get('issuer'));

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
        'Make sure you enter the full JSON response from the token endpoint, not just the access token',
        $tokenResponse);
    }

    // Check that the response includes an access token
    if(!isset($response['access_token'])) {
      return $this->_respondWithError($this->baseRoute,
        'The token response does not contain an access token. Check for any error messages in the token response and try again.',
        $tokenResponse);
    }

    if(!isset($opts['allowRefreshToken'])) {
      // Check that the response does not include a refresh token
      if(isset($response['refresh_token'])) {
        return $this->_respondWithError($this->baseRoute,
          'We found a refresh token, but you should not have one at this point. Make sure you\'ve followed the instructions for this exercise exactly and are requesting only an access token.',
          $tokenResponse);
      }
    }

    // Check that the response does not include an ID token
    if(isset($response['id_token'])) {
      return $this->_respondWithError($this->baseRoute,
        'We found an ID token, but you should not have one at this point. Make sure you\'ve followed the instructions for this exercise exactly and are requesting only an access token.',
        $tokenResponse);
    }

    if($provider != 'auth0') {
      $scopesReturned = !empty($response['scope']) ? explode(' ', $response['scope']) : [];
      if(!is_array($scopesReturned) || !count($scopesReturned) || !count(array_intersect($scopes, $scopesReturned))) {
        return $this->_respondWithError($this->baseRoute,
          'Make sure you\'ve requested one of the scopes you made public. You can find the list of scopes we\'re looking for in the first exercise.',
          $tokenResponse);
      }
    }

    // Now parse the access token

    $this->tokenString = $tokenString = $response['access_token'];

    // Check if the access token looks like an Auth0 token without a custom audience
    if(preg_match('/^([^\.]+)\.\.([^\.]+)\.([^\.]+)\.([^\.]+)$/', $tokenString)) {
      return $this->_respondWithError($this->baseRoute,
        'The access token returned looks like an Opaque Auth0 access token, which means you probably didn\'t set the default audience on your account as described in the getting started exercise.',
        $tokenString);
    }


    if(!preg_match('/^([^\.]+)\.([^\.]+)\.([^\.]+)$/', $tokenString, $match)) {
      return $this->_respondWithError($this->baseRoute,
        'The access token returned does not look like a JWT. This tool will only with with JWT access tokens.',
        $tokenString);
    }

    $this->header = $header = json_decode(Base64Url::decode($match[1]), true);
    $this->claims = $claims = json_decode(Base64Url::decode($match[2]), true);

    if(!$claims || !is_array($claims)) {
      return $this->_respondWithError($this->baseRoute,
        'Something went wrong trying to parse the claims in the token.',
        $tokenString);
    }

    $this->claimsString = $claimsString = json_encode($claims, JSON_PP);

    if(!isset($opts['clientCredentials'])) {
      switch($provider) {
        case 'okta':
          // Check for a uid and sub claim
          if(!isset($claims['uid']) || !isset($claims['sub'])) {
            return $this->_respondWithError($this->baseRoute,
              'The access token doesn\'t look right. Try again by using the authorization code flow.',
              $claimsString);
          }
          break;
        case 'auth0':
          // Check for a sub claim and make sure gty != 'client-credentials'
          if(!isset($claims['sub']) || (isset($claims['gty']) && $claims['gty'] == 'client-credentials')) {
            return $this->_respondWithError($this->baseRoute,
              'The access token doesn\'t look right. Try again by using the authorization code flow.',
              $claimsString);
          }
          break;
      }
    }

    // Now attempt to verify the token using the JWKs from the metadata URL
    try {
      $this->tokenData = $tokenData = JWT::decode($tokenString, JWK::parseKeySet($this->session->get('jwks')), ['RS256']);
    } catch(\Exception $e) {
      return $this->_respondWithError($this->baseRoute,
        'There was an error validating the JWT: '.$e->getMessage(),
        $claimsString);
    }

    $this->_updateEmailForIssuer($claims['sub']);
    $this->session->remove('authorizationURLSuccess');
    $this->session->remove('authorizationURL');

    return null;
  }

}
