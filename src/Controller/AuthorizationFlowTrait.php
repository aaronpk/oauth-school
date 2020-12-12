<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

trait AuthorizationFlowTrait {

  public function index(): Response {

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/authorization-code.html.twig', [
      'page_title' => $this->pageTitle,
      'issuer' => $issuer,
      'scopes' => $scopes,
      'base_route' => $this->baseRoute,
    ]);
  }


  public function authz(Request $request): Response {

    $redirectToRoute = $this->baseRoute;

    $scopes = $this->session->get('scopes');

    $authorizationURL = trim($request->request->get('authorizationURL'));

    if(!$authorizationURL) {
      return $this->_respondWithError($redirectToRoute,
        'Please enter the authorization URL',
        $authorizationURL);
    }

    $authorizationURL = preg_replace('/[\s+]/', '', $authorizationURL);

    $this->addFlash('authorizationURL', $authorizationURL);

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

    parse_str($url['query'], $query);

    $required = ['response_type', 'scope', 'client_id', 'state', 'redirect_uri', 'code_challenge', 'code_challenge_method'];

    $missing = false;
    foreach($required as $key) {
      if(empty($query[$key])) {
        $missing = true;
      }
    }

    if($missing) {
      return $this->_respondWithError($redirectToRoute,
        'It looks like you are missing some query string parameters in the URL',
        $authorizationURL);
    }

    $diff = array_diff(array_keys($query), $required);

    if(count($diff)) {
      return $this->_respondWithError($redirectToRoute,
        'It looks like you have some extra query string parameters in your URL, or some are misspelled',
        $authorizationURL);
    }

    // Everything checked out, log a success
    return $this->_respondWithSuccess(
      $redirectToRoute,
      'Great! You built the URL, now you\'re ready to go log in. Click the login link to be taken to the authorization server and log in',
      $authorizationURL,
      ['loginURL' => $authorizationURL]
    );

  }

}
