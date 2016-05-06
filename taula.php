<?php
//Connexió a la BD phpmon i nom de la taula.
$config = parse_ini_file('config.ini');
$conn=(connectar($config));
$taula = "paquet";

crearTaula($conn,$taula);
?>