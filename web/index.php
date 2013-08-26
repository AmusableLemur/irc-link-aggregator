<?php

require_once __DIR__."/../vendor/autoload.php";

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

$app = new Silex\Application(array(
    "debug" => true
));

$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
    "db.options" => array (
        "driver"    => "pdo_mysql",
        "host"      => "localhost",
        "dbname"    => "suitup",
        "user"      => "root",
        "password"  => "",
        "charset"   => "utf8"
    )
));

$app->register(new Silex\Provider\SecurityServiceProvider());

$app->register(new Silex\Provider\TwigServiceProvider(), array(
    "twig.path" => __DIR__."/../views",
));

$app["password"] = function() {
    $encoder = new MessageDigestPasswordEncoder();
    $password = "CHANGE_ME";
    $password = md5($password.date("Y-m-d"));
    $password = substr($password, 0, 12);

    return $encoder->encodePassword($password, "");
};

$app["security.firewalls"] = array(
    "unsecured" => array(
        "pattern" => "^/submit",
        "anonymous" => true
    ),
    "secured" => array(
        "pattern" => "^/",
        "http" => true,
        "users" => array(
            "user" => array("ROLE_USER", $app["password"]),
        )
    )
);

$app['security.access_rules'] = array(
    array("^.*$", "IS_AUTHENTICATED_ANONYMOUSLY", "https")
);

$app->get("/", function() use($app) {
    $query = $app["db"]->prepare("SELECT * FROM links ORDER BY id DESC");

    $query->execute();

    return $app["twig"]->render("index.html.twig", array(
        "links" => $query->fetchAll(PDO::FETCH_ASSOC)
    ));
});

$app->post("/submit", function(Request $request) use($app) {
    if ($request->get("key") == "CHANGE_ME") {
        $query = $app["db"]->prepare(
            "INSERT INTO links (
                url,
                nick,
                time
            ) VALUES (
                :url,
                :nick,
                :time
            )"
        );

        $query->bindValue("url", $request->get("url"));
        $query->bindValue("nick", $request->get("nick"));
        $query->bindValue("time", time());
        $query->execute();
    }

    return "Saved!";
});

$app->run();
