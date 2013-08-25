<?php

require_once __DIR__."/../vendor/autoload.php";

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

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

$app->register(new Silex\Provider\TwigServiceProvider(), array(
    "twig.path" => __DIR__."/../views",
));

$app->get("/", function() use($app) {
    $query = $app["db"]->prepare("SELECT * FROM links ORDER BY id DESC");

    $query->execute();

    return $app["twig"]->render("index.html.twig", array(
        "links" => $query->fetchAll(PDO::FETCH_ASSOC)
    ));
});

$app->post("/", function(Request $request) use($app) {
    if ($request->get("key") == "secret") {
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
        $query->bindValue("time", $request->get("time"));
        $query->execute();
    }

    return "Saved!";
});

$app->run();
