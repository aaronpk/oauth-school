<?php
namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use GuzzleHttp;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use ORM;

class SPAFlowController extends NativeFlowController {

  protected $pageTitle = 'Authorization Code Flow for Single-Page Apps';
  protected $baseRoute = 'spa';
  protected $confidentialClient = false;
  protected static $baseRouteStatic = 'spa';

}
