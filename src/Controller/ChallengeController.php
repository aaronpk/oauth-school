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

  protected $maxIssuedAt = '2021-08-12T23:00:00-0700';

  protected $initialStatus = [
    'issued_before' => false,
    'active' => false,
    'confidential' => false,
    'lifetime' => false,
    'scope' => false,
    'custom_claim' => false,
  ];


  protected function _getParticipant($issuer) {
    $p = ORM::for_table('challenge_participants')->where('issuer', $issuer)->find_one();

    if(!$p) {
      $p = ORM::for_table('challenge_participants')->create();
      $p->issuer = $issuer;
      $p->created_at = date('Y-m-d H:i:s');
      $p->attempts = 0;
    }

    $p->updated_at = date('Y-m-d H:i:s');

    return $p;
  }


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



    $this->session->set('challenge-1-issuer', $issuer);


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
    $record = $this->_getParticipant($issuer);
    $record->complete = $this->session->get('challenge-1') == 'complete';
    foreach($status as $k=>$v) {
      $record->{'status_'.$k} = $v;
    }
    $record->attempts++;
    $record->claims = $claimsJson;
    $record->save();

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
    // Make sure they actually completed the challenge
    if($this->session->get('challenge-1') != 'complete')
      return $this->redirectToRoute('challenge/1');

    $claims = json_decode($this->session->get('challenge-1-claims'), true);

    $data['email'] = '';
    if(isset($claims['sub']) && preg_match('/.+@.+\..+/', $claims['sub']))
      $data['email'] = $claims['sub'];

    $data['name'] = $claims['name'] ?? '';

    $data['address'] = '';
    $data['phone'] = '';

    $fields = ['email','name','address','phone'];
    foreach($fields as $f) {
      if($this->session->get($f))
        $data[$f] = $this->session->get($f);
    }

    $complete = (in_array(false, $data) === false);

    // Add this back after checking if the fields they filled out were complete
    $data['prize'] = '';
    if($this->session->get('prize'))
      $data['prize'] = $this->session->get('prize');

    // Figure out if they were the first winner
    $issuer = $this->session->get('challenge-1-issuer');
    $participant = $this->_getParticipant($issuer);
    if($participant->id)
      $winners = ORM::for_table('challenge_winners')
        ->where('archived', 0)
        ->where_not_equal('participant_id', $participant->id)
        ->count();
    else
      $winners = ORM::for_table('challenge_winners')
        ->where('archived', 0)
        ->count();
    $first_winner = $winners == 0;

    return $this->render('challenges/challenge-1-claim.html.twig', [
      'page_title' => 'Claim your prize!',
      'base_route' => $this->baseRoute,
      'claims' => $claims,
      'data' => $data,
      'first_winner' => $first_winner,
      'complete' => $complete,
    ]);
  }

  public function challenge1claimsave(Request $request): Response {
    if($this->session->get('challenge-1') != 'complete')
      return $this->redirectToRoute('challenge/1');


    $fields = ['email','name','address','phone','prize'];

    foreach($fields as $f) {
      $this->session->set($f, $request->request->get($f));
    }

    $issuer = $this->session->get('challenge-1-issuer');
    $participant = $this->_getParticipant($issuer);

    $winner = ORM::for_table('challenge_winners')->where('participant_id', $participant->id)->find_one();
    if(!$winner) {
      $winner = ORM::for_table('challenge_winners')->create();
      $winner->participant_id = $participant->id;
      $winner->created_at = date('Y-m-d H:i:s');
    }
    foreach($fields as $f) {
      $winner->{$f} = $request->request->get($f);
    }
    $winner->save();


    return $this->redirectToRoute('challenge/1/claim');
  }

  public function challenge1reset(Request $request): Response {
    $this->session->clear();
    return $this->redirectToRoute('challenge/1/start');
  }

}
