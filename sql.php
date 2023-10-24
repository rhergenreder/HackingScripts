<?php

error_reporting(E_ALL);

if (php_sapi_name() === "cli") {
  $username = $argv[1];
  $password = $argv[2];
  $database = $argv[3] ?? null;
  $host = $argv[4] ?? "localhost";
  $query = $argv[5] ?? "SELECT @@version";
} else {
  $username = $_REQUEST["username"]; 
  $password = $_REQUEST["password"];
  $database = (isset($_REQUEST["database"]) ? $_REQUEST["database"] : null);
  $host     = (isset($_REQUEST["host"]) ? $_REQUEST["host"] : "localhost");
  $query    = (isset($_REQUEST["query"]) ? $_REQUEST["query"] : "SELECT @@version");  
}

$link = mysqli_connect($host, $username, $password, $database);
if (!$link) {
  die("Error connecting to mysql: " . mysqli_connect_error() . " (" . mysqli_connect_errno() . ")");
}

$res = mysqli_query($link, $query);
if (!$res) {
  die("Error executing query: " . mysqli_error($link));
}

while ($row = $res->fetch_assoc()) {
  var_dump($row);
}

mysqli_close($link);
?>
