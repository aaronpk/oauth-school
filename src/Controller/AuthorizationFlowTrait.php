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
    ]);
  }

}
