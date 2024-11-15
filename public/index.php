<?php
define('JSON_PP', JSON_PRETTY_PRINT+JSON_UNESCAPED_SLASHES);

use App\Kernel;
use Symfony\Component\Dotenv\Dotenv;
use Symfony\Component\ErrorHandler\Debug;
use Symfony\Component\HttpFoundation\Request;

require dirname(__DIR__).'/vendor/autoload.php';

(new Dotenv())->bootEnv(dirname(__DIR__).'/.env');

if ($_SERVER['APP_DEBUG']) {
    umask(0000);

    Debug::enable();
}

$db = parse_url($_ENV['DATABASE_URL']);
ORM::configure('driver_options', array(PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES utf8'));
ORM::configure($db['scheme'].':host='.$db['host'].';dbname='.trim($db['path'],'/'));
ORM::configure('username', $db['user']);
ORM::configure('password', $db['pass']);

$kernel = new Kernel($_SERVER['APP_ENV'], (bool) $_SERVER['APP_DEBUG']);
$request = Request::createFromGlobals();

Request::setTrustedProxies(
    [$request->server->get('REMOTE_ADDR')],
    Request::HEADER_X_FORWARDED_ALL ^ Request::HEADER_X_FORWARDED_HOST
);

$response = $kernel->handle($request);
$response->send();
$kernel->terminate($request, $response);
