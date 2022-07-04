<?php
namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use ORM;

class ExerciseController extends AbstractController {

  protected $session;

  protected $requireCustomScopeInAuthz = true;

  public function __construct(SessionInterface $session)
  {
    $this->session = $session;
  }

  protected function _getIssuer() {
    $issuer = $this->session->get('issuer');
    if($issuer) {
      $record = ORM::for_table('issuers')->where('uri', $issuer)->find_one();
      if($record) {
        return $record;
      }
    }

    return null;
  }

  protected function _updateEmailForIssuer($email) {
    $issuer = $this->_getIssuer();
    if($issuer) {
      $issuer->email = $email;
      $issuer->save();
    }
  }

  protected function _providerFromIssuer($issuer) {
    $host = parse_url($issuer, PHP_URL_HOST);

    if(preg_match('/.+\.okta\.com$/', $host))
      return 'okta';

    if(preg_match('/.+\.auth0\.com$/', $host))
      return 'auth0';

    return 'unknown';
  }

  protected function _additionalAuthzChecks($authorizationURL, $queryParams, $scopesRequested) {
    // Override to insert additional checks of the authorization request.
    // Return true to indicate all checks passed.
    return true;
  }

  protected function _logResult($test, $success, $message, $data) {
    $record = ORM::for_table('results')->create();
    $record->issuer_id = ($this->_getIssuer() ? $this->_getIssuer()->id : 0);
    $record->success = $success;
    $record->test = $test;
    $record->message = $message;
    $record->data = $data;
    $record->created_at = date('Y-m-d H:i:s');
    $record->save();
  }

  protected function _respondWithError($route, $error, $data='') {
    $this->addFlash('error', $error);
    $this->_logResult($route, 0, $error, $data);
    return $this->redirectToRoute($route);
  }

  protected function _respondWithSuccess($route, $message, $data, $flash=[]) {
    $this->addFlash('success', $message);
    $this->_logResult($route, 1, $message, $data);
    if($flash) {
      foreach($flash as $k=>$v) {
        $this->addFlash($k, $v);
      }
    }
    return $this->redirectToRoute($route);
  }

}
