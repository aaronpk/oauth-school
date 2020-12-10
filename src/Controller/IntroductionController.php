<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;

class IntroductionController extends AbstractController {

  private $session;

  public function __construct(SessionInterface $session)
  {
    $this->session = $session;
  }

  public function index(): Response {

    $issuer = $this->session->get('issuer');
    $scopes = $this->session->get('scopes');

    return $this->render('exercises/introduction.html.twig', [
      'issuer' => $issuer,
      'scopes' => $scopes,
      'scopeString' => implode(' ', $scopes ?: []),
      'numScopes' => count($scopes ?: []),
    ]);
  }

  public function save(Request $request): Response {

    $issuer = $request->request->get('issuer');

    if(!$issuer) {
      $this->addFlash('error', 'Please provide an issuer URL');
      return $this->redirectToRoute('introduction');
    }

    // Check that it's a URL
    if(!preg_match('/^https?:\/\/[^\/]+/', $issuer)) {
      $this->addFlash('error', 'The issuer identifier must be a URL');
      return $this->redirectToRoute('introduction');
    }

    $metadataURL = $issuer.'/.well-known/oauth-authorization-server';

    // Fetch the URL
    $client = new GuzzleHttp\Client();
    $res = $client->request('GET', $metadataURL, [
      'http_errors' => false,
    ]);
    $code = $res->getStatusCode();

    if($code != 200) {
      $this->addFlash('error', 'The metadata URL ('.$metadataURL.') returned HTTP '.$code.'. Double check you entered the correct issuer URL');
      return $this->redirectToRoute('introduction');
    }

    $metadata = json_decode($res->getBody(), true);

    if(!$metadata) {
      $this->addFlash('error', 'The metadata URL does not contain valid JSON');
      return $this->redirectToRoute('introduction');
    }

    // Check for the JWKs URL
    if(!isset($metadata['jwks_uri'])) {
      $this->addFlash('error', 'The metadata URL does not contain a jwks_uri');
      return $this->redirectToRoute('introduction');
    }

    // Attempt to fetch the keys
    $jwksres = $client->request('GET', $metadata['jwks_uri'], [
      'http_errors' => false,
    ]);
    $code = $jwksres->getStatusCode();

    if($code != 200) {
      $this->addFlash('error', 'The jwks_uri ('.$metadata['jwks_uri'].') returned HTTP '.$code.'. Double check you entered the correct issuer URL');
      return $this->redirectToRoute('introduction');
    }

    $jwks = json_decode($jwksres->getBody(), true);

    if(!$jwks) {
      $this->addFlash('error', 'The jwks_uri does not contain valid JSON');
      return $this->redirectToRoute('introduction');
    }

    // Check for the custom scope
    if(!isset($metadata['scopes_supported'])) {
      $this->addFlash('error', 'The metadata URL does not contain the "scopes_supported" property');
      return $this->redirectToRoute('introduction');
    }

    $openIDScopes = ['openid','profile','email','address','phone','offline_access'];
    $customScopes = array_diff($metadata['scopes_supported'], $openIDScopes);
    if(count($customScopes) == 0) {
      $this->addFlash('error', 'We didn\'t find any custom scopes defined on your OAuth server. Ensure you\'ve created at least one custom scope and set it to "Include in public metadata".');
      return $this->redirectToRoute('introduction');
    }

    $count = count($customScopes);
    $this->session->set('issuer', $issuer);
    $this->session->set('scopes', $customScopes);
    $this->session->set('jwks', $jwks);

    return $this->redirectToRoute('introduction');
  }

}
