<?php

error_reporting(E_ALL);

if (php_sapi_name() === "cli") {
  $username = $argv[1];
  $password = $argv[2];
  $database = $argv[3] ?? null;
  $host = $argv[4] ?? "localhost";
  $query = $argv[5] ?? "SELECT @@version";
  $dump_all = $query === "mysqldump";
} else {
  $username = $_REQUEST["username"]; 
  $password = $_REQUEST["password"];
  $database = (isset($_REQUEST["database"]) ? $_REQUEST["database"] : null);
  $host     = (isset($_REQUEST["host"]) ? $_REQUEST["host"] : "localhost");
  $query    = (isset($_REQUEST["query"]) ? $_REQUEST["query"] : "SELECT @@version");
  $dump_all = isset($_REQUEST["dumpAll"]);
}

$link = mysqli_connect($host, $username, $password, $database);
if (!$link) {
  die("Error connecting to mysql: " . mysqli_connect_error() . " (" . mysqli_connect_errno() . ")");
}

if ($dump_all) {
  $res = mysqli_query($link, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='$database'");
  $tables = array();
  while ($row = $res->fetch_assoc()) {
    $tables[] = $row["TABLE_NAME"];
  }  

  foreach ($tables as $tableName) {
    echo "-- DATA FOR TABLE: tableName\n";
    $res = mysqli_query($link, "SELECT * FROM $tableName");
    while ($row = $res->fetch_assoc()) {
      var_dump($row);
    }
    echo "-- --------------------------\n\n";
  }
  
} else {
  $res = mysqli_query($link, $query);
  if (!$res) {
    die("Error executing query: " . mysqli_error($link));
  }
}

while ($row = $res->fetch_assoc()) {
  var_dump($row);
}

mysqli_close($link);
?>
