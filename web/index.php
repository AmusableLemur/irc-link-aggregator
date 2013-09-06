<?php

require_once __DIR__."/../vendor/autoload.php";

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Encoder\MessageDigestPasswordEncoder;

$app = new Silex\Application();

try {
    $app->register(new Igorw\Silex\ConfigServiceProvider(__DIR__."/../config.json"));
} catch (InvalidArgumentException $e) {
    die("Configuration file is invalid.");
}

$app->register(new Silex\Provider\DoctrineServiceProvider(), array(
    "db.options" => $app["database"]
));

$app->register(new Silex\Provider\SecurityServiceProvider());

$app->register(new Silex\Provider\TwigServiceProvider(), array(
    "twig.path" => __DIR__."/../views",
));

$app["embedly"] = $app->share(function() use($app) {
    return new Embedly\Embedly(array(
        "user_agent" => "Mozilla/5.0 (compatible; irc-link-aggregator/1.0)",
        "key" => $app["embedly_key"]
    ));
});

$app["password_encoder"] = $app->share(function() {
    return new MessageDigestPasswordEncoder();
});

$app["password"] = function() use($app) {
    $password = $app["secret"];
    $password = md5($password.date("Y-m-d"));
    
    return substr($password, 0, 12);
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
            "user" => array("ROLE_USER", $app["password_encoder"]->encodePassword($app["password"], "")),
        )
    )
);

if ($app["force_https"]) {
    $app["security.access_rules"] = array(
        array("^.*$", "IS_AUTHENTICATED_ANONYMOUSLY", "https")
    );
}

$app->get("/", function() use($app) {
    $query = $app["db"]->prepare("SELECT * FROM links ORDER BY id DESC");

    $query->execute();

    $links = $query->fetchAll(PDO::FETCH_ASSOC);

    array_walk($links, function(&$link) use($app) {
        $link["meta"] = unserialize($link["meta"]);
    });

    return $app["twig"]->render("index.html.twig", array(
        "links" => $links
    ));
});

$app->post("/submit", function(Request $request) use($app) {
    if ($request->get("key") == $app["secret"]) {
        $meta = array();

        if (isset($app["embedly_key"]) && $app["embedly_key"] != "CHANGE_ME") {
            $meta = $app["embedly"]->oembed($request->get("url"));
        }

        $query = $app["db"]->prepare(
            "INSERT INTO links (
                url,
                nick,
                time,
                meta
            ) VALUES (
                :url,
                :nick,
                :time,
                :meta
            )"
        );

        $query->bindValue("url", $request->get("url"));
        $query->bindValue("nick", $request->get("nick"));
        $query->bindValue("time", time());
        $query->bindValue("meta", serialize($meta));
        $query->execute();

        return new Response("Saved!", 201);
    }

    return new Response("Unauthorized", 401);
});

$app->run();
