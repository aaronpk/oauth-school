<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use DateTime;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class ChallengeController extends ExerciseController {

  use AuthorizationFlowTrait;

  protected $pageTitle = 'OAuth Workshop Challenge';
  protected $baseRoute = 'challenge';

  protected $maxIssuedAt = '2021-06-25T19:00:00Z';

  protected $initialStatus = [
    'issued_before' => false,
    'active' => false,
    'confidential' => false,
    'lifetime' => false,
    'scope' => false,
    'custom_claim' => false,
  ];


  public function challenge(Request $request): Response {


    return $this->render('challenges/index.html.twig', [
      'page_title' => $this->pageTitle,
      'base_route' => $this->baseRoute,
    ]);
  }

  public function challenge1(Request $request): Response {
    return $this->render('challenges/1.html.twig', [
      'page_title' => $this->pageTitle,
      'base_route' => $this->baseRoute,
      'max_issued_at' => new DateTime($this->maxIssuedAt),
    ]);
  }

  public function challenge1start(Request $request): Response {

    $status = $this->initialStatus;

    if($this->session->get('challenge-1') == 'complete') {
      foreach($status as $k=>$v) {
        $status[$k] = true;
      }
    }

    return $this->render('challenges/challenge-1.html.twig', [
      'page_title' => $this->pageTitle,
      'base_route' => $this->baseRoute,
      'max_issued_at' => new DateTime($this->maxIssuedAt),
      'status' => $status,
      'claims_json' => $this->session->get('challenge-1-claims'),
      'complete' => ($this->session->get('challenge-1') == 'complete'),
    ]);
  }

  public function challenge1save(Request $request): Response {

    $route = 'challenge/1/start';

    if($request->isMethod('GET')) {
      return $this->redirectToRoute($route);
    }

    $tokenString = $this->tokenString = $request->request->get('token');

    if(!preg_match('/^(.+)\.(.+)\.(.+)$/', $tokenString, $match)) {
      return $this->_respondWithError($route,
        'The access token you entered does not look like a JWT. Make sure you enter a valid Okta access token',
        $tokenString);
    }

    $this->header = $header = json_decode(base64_decode($match[1]), true);
    $this->claims = $claims = json_decode(base64_decode($match[2]), true);

    if(!$claims || !is_array($claims)) {
      return $this->_respondWithError($route,
        'Something went wrong trying to parse the claims in the token.',
        $tokenString);
    }

    $this->claimsString = $claimsString = json_encode($claims, JSON_PP);

    if(!isset($claims['uid']) || !isset($claims['sub'])) {
      return $this->_respondWithError($route,
        'The access token is missing some required claims. Try again by using the authorization code flow.',
        $claimsString);
    }

    // Check for an expired token now
    if(!isset($claims['exp']) || $claims['exp'] < time()) {
      return $this->_respondWithError($route,
        'The access token is expired. Try again after getting a fresh access token.',
        $claimsString);
    }

    // Find the issuer of the token
    if(!isset($claims['iss'])) {
      return $this->_respondWithError($route,
        'This access token has no issuer claim. Make sure you enter a valid Okta access token.',
        $claimsString);
    }

    $issuer = $claims['iss'];

    // Fetch the OAuth server metadata
    $metadataURL = $issuer.'/.well-known/oauth-authorization-server';

    // Fetch the URL
    try {
      $client = new GuzzleHttp\Client();
      $res = $client->request('GET', $metadataURL, [
        'http_errors' => false,
      ]);
    } catch(\Exception $e) {
      return $this->_respondWithError($redirectToRoute,
        'There was an error trying to fetch the OAuth server metadata: '.$e->getMessage(),
        $issuer);
    }
    $code = $res->getStatusCode();

    if($code != 200) {
      return $this->_respondWithError($route,
        'The metadata URL ('.$metadataURL.') returned HTTP '.$code.'. Double check you entered the correct issuer URL',
        $issuer);
    }

    $metadata = json_decode($res->getBody(), true);

    if(!$metadata) {
      return $this->_respondWithError($route,
        'The metadata URL does not contain valid JSON',
        $issuer);
    }

    // Check for the JWKs URL
    if(!isset($metadata['jwks_uri'])) {
      return $this->_respondWithError($route,
        'The metadata URL does not contain a jwks_uri',
        $issuer);
    }

    // Attempt to fetch the keys
    $jwksres = $client->request('GET', $metadata['jwks_uri'], [
      'http_errors' => false,
    ]);
    $code = $jwksres->getStatusCode();

    if($code != 200) {
      return $this->_respondWithError($route,
        'The jwks_uri ('.$metadata['jwks_uri'].') returned HTTP '.$code.'. Double check you entered the correct issuer URL',
        $issuer);
    }

    $jwks = json_decode($jwksres->getBody(), true);

    if(!$jwks) {
      return $this->_respondWithError($route,
        'The jwks_uri does not contain valid JSON',
        $issuer);
    }

    // Now attempt to verify the token using the JWKs from the metadata URL
    try {
      $this->tokenData = $tokenData = JWT::decode($tokenString, JWK::parseKeySet($jwks), ['RS256']);
    } catch(\Exception $e) {
      return $this->_respondWithError($route,
        'There was an error validating the JWT: '.$e->getMessage(),
        $claimsString);
    }

    // Make sure this is a unique issuer




    $status = $this->initialStatus;
    $status['active'] = true; // JWT validation checks this

    // Lifetime check
    if(isset($claims['exp']) && isset($claims['iat']) && $claims['exp'] - $claims['iat'] >= 7200) {
      $status['lifetime'] = true;
    }

    // Make sure this wasn't issued after the challenge ends
    if(isset($claims['iat']) && $claims['iat'] < strtotime($this->maxIssuedAt)) {
      $status['issued_before'] = true;
    }

    // Make sure this is issued to a confidential client
    if(isset($metadata['introspection_endpoint'])) {
      try {
        $client = new GuzzleHttp\Client();
        $res = $client->request('POST', $metadata['introspection_endpoint'], [
          'http_errors' => false,
          'form_params' => [
            'token' => $tokenString,
            'client_id' => $claims['cid'],
          ],
        ]);
      } catch(\Exception $e) {
      }
      $code = $res->getStatusCode();

      if($code == 401) {
        // Attempt to introspect the token, which should fail, since introspection in this case requires a client secret.
        // This is how we can check that they used a confidential client for this exercise and not a public client.
        $status['confidential'] = true;
      }
    }

    // Look for the required scope
    if(isset($claims['scp']) && is_array($claims['scp']) && in_array('workshop', $claims['scp'])) {
      $status['scope'] = true;
    }

    // Look for the required custom claim
    if(isset($claims['favorite_color'])) {
      $status['custom_claim'] = true;
    }

    // If all values are true (if there are no false values) they succeeded!
    if(in_array(false, $status, true) === false) {
      $this->session->set('challenge-1', 'complete');
    } else {
      $this->session->remove('challenge-1');
    }

    $claimsJson = json_encode($claims, JSON_PRETTY_PRINT+JSON_UNESCAPED_SLASHES);
    $this->session->set('challenge-1-claims', $claimsJson);

    // Log the status of this attempt in the database




    return $this->render('challenges/challenge-1.html.twig', [
      'page_title' => $this->pageTitle,
      'base_route' => $this->baseRoute,
      'max_issued_at' => new DateTime($this->maxIssuedAt),
      'status' => $status,
      'claims_json' => $claimsJson,
      'complete' => ($this->session->get('challenge-1') == 'complete'),
    ]);
  }


  public function challenge1claim(Request $request): Response {


    return $this->render('challenges/challenge-1-claim.html.twig', [
      'page_title' => $this->pageTitle,
      'base_route' => $this->baseRoute,
    ]);
  }

  public function challenge1reset(Request $request): Response {
    $this->session->remove('challenge-1');
    $this->session->remove('challenge-1-claims');
    return $this->redirectToRoute('challenge/1/start');
  }

}
