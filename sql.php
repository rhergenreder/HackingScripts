<?php

error_reporting(E_ALL);
if (function_exists("mysqli_connect")) {
  $db_driver = "mysqli";
} else if (class_exists("PDO")) {
  $db_driver = "PDO";
} else {
  die("Neither mysqli nor PDO could be found. Exiting.");
}

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

if ($db_driver === "mysqli") {
  $link = mysqli_connect($host, $username, $password, $database);
  if (!$link) {
    die("Error connecting to mysql: " . mysqli_connect_error() . " (" . mysqli_connect_errno() . ")");
  }
} else if ($db_driver === "PDO") {
  $databaseStr = $database ? ";dbname=$database" : "";
  $link = new PDO("mysql:host=$host$databaseStr", $username, $password);
  $link->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
}

if ($dump_all) {
  $tables = array();  

  if ($db_driver === "mysqli") {
    $res = mysqli_query($link, "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='$database'");
    while ($row = $res->fetch_assoc()) {
      $tables[] = $row["TABLE_NAME"];
    }  
  } else if ($db_driver === "PDO") {
    $stmt = $link->query("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='$database'");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
      $tables[] = $row["TABLE_NAME"];
    }
  }

  foreach ($tables as $tableName) {
    echo "-- DATA FOR TABLE: tableName\n";
    if ($db_driver === "mysqli") {
      $res = mysqli_query($link, "SELECT * FROM $tableName");
      while ($row = $res->fetch_assoc()) {
        print_r($row);
      }
    } else if ($db_driver === "PDO") {
      $stmt = $link->query("SELECT * FROM $tableName");
      while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        print_r($row);
      }
    }
    echo "-- --------------------------\n\n";
  }
  
} else {
  if ($db_driver === "mysqli") {
    $res = mysqli_query($link, $query);
    if (!$res) {
      die("Error executing query: " . mysqli_error($link));
    }

    while ($row = $res->fetch_assoc()) {
      print_r($row);
    }
  } else if ($db_driver === "PDO") {
    $stmt = $link->query($query);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
      print_r($row);
    }
  }
}

if ($db_driver === "mysqli") {
  mysqli_close($link);
}
?>
